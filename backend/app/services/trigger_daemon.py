"""Trigger Daemon — evaluates all agent triggers in a single background loop.

Replaces the separate heartbeat, scheduler, and supervision reminder services
with a unified trigger evaluation engine. Runs as an asyncio background task.

Every 15 seconds:
  1. Load all enabled triggers from DB
  2. Evaluate each trigger (cron/once/interval/poll/on_message)
  3. Group fired triggers by agent_id (30s dedup window)
  4. Invoke each agent once with all its fired triggers as context
"""

import asyncio
import logging
import uuid
from datetime import datetime, timezone, timedelta

from croniter import croniter
from sqlalchemy import select

from app.database import async_session
from app.models.trigger import AgentTrigger
from app.models.agent import Agent

logger = logging.getLogger(__name__)

TICK_INTERVAL = 15  # seconds
DEDUP_WINDOW = 30   # seconds — same agent won't be invoked twice within this window
MAX_AGENT_CHAIN_DEPTH = 5  # A→B→A→B→A max depth before stopping

# Track last invocation time per agent to enforce dedup window
_last_invoke: dict[uuid.UUID, datetime] = {}


# ── Trigger Evaluation ──────────────────────────────────────────────

async def _evaluate_trigger(trigger: AgentTrigger, now: datetime) -> bool:
    """Return True if this trigger should fire right now."""
    if not trigger.is_enabled:
        return False
    if trigger.expires_at and now >= trigger.expires_at:
        # Auto-disable expired triggers
        return False
    if trigger.max_fires is not None and trigger.fire_count >= trigger.max_fires:
        return False

    # Cooldown check
    if trigger.last_fired_at:
        cooldown = timedelta(seconds=trigger.cooldown_seconds)
        if (now - trigger.last_fired_at) < cooldown:
            return False

    cfg = trigger.config or {}
    t = trigger.type

    if t == "cron":
        expr = cfg.get("expr", "* * * * *")
        base = trigger.last_fired_at or trigger.created_at
        try:
            cron = croniter(expr, base)
            next_run = cron.get_next(datetime)
            return now >= next_run
        except Exception as e:
            logger.warning(f"Invalid cron expr '{expr}' for trigger {trigger.name}: {e}")
            return False

    elif t == "once":
        at_str = cfg.get("at")
        if not at_str:
            return False
        try:
            at = datetime.fromisoformat(at_str)
            if at.tzinfo is None:
                at = at.replace(tzinfo=timezone.utc)
            return now >= at and trigger.fire_count == 0
        except Exception:
            return False

    elif t == "interval":
        minutes = cfg.get("minutes", 30)
        base = trigger.last_fired_at or trigger.created_at
        return (now - base) >= timedelta(minutes=minutes)

    elif t == "poll":
        interval_min = cfg.get("interval_min", 5)
        base = trigger.last_fired_at or trigger.created_at
        if (now - base) < timedelta(minutes=interval_min):
            return False
        # Actual HTTP poll + change detection
        return await _poll_check(trigger)

    elif t == "on_message":
        return await _check_new_agent_messages(trigger)

    return False


async def _poll_check(trigger: AgentTrigger) -> bool:
    """HTTP poll: fetch URL, extract value via json_path, detect change.
    
    Persists _last_value into the trigger's config JSONB so it survives
    across process restarts.
    """
    import httpx
    cfg = trigger.config or {}
    url = cfg.get("url")
    if not url:
        return False

    try:
        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.request(cfg.get("method", "GET"), url, headers=cfg.get("headers", {}))
            resp.raise_for_status()

        data = resp.json()
        json_path = cfg.get("json_path", "$")
        current_value = _extract_json_path(data, json_path)
        current_str = str(current_value)

        fire_on = cfg.get("fire_on", "change")
        should_fire = False

        if fire_on == "match":
            should_fire = current_str == str(cfg.get("match_value", ""))
        else:  # "change"
            last_value = cfg.get("_last_value")
            # First poll — don't fire, just record baseline
            if last_value is None:
                should_fire = False
            else:
                should_fire = current_str != last_value

        # Persist _last_value to DB so it survives restarts
        cfg["_last_value"] = current_str
        try:
            from sqlalchemy import update
            async with async_session() as db:
                await db.execute(
                    update(AgentTrigger)
                    .where(AgentTrigger.id == trigger.id)
                    .values(config=cfg)
                )
                await db.commit()
        except Exception as e:
            logger.warning(f"Failed to persist poll _last_value for {trigger.name}: {e}")

        return should_fire

    except Exception as e:
        logger.warning(f"Poll failed for trigger {trigger.name}: {e}")
        return False


def _extract_json_path(data, path: str):
    """Simple JSONPath extraction: $.key.subkey → data['key']['subkey']."""
    if path == "$" or not path:
        return data
    parts = path.lstrip("$.").split(".")
    current = data
    for part in parts:
        if isinstance(current, dict):
            current = current.get(part)
        elif isinstance(current, list) and part.isdigit():
            current = current[int(part)]
        else:
            return None
    return current


async def _check_new_agent_messages(trigger: AgentTrigger) -> bool:
    """Check if there are new agent-to-agent messages matching this trigger.
    
    Stores the actual message content in trigger.config['_matched_message']
    so the invocation context can include it.
    """
    from app.models.audit import ChatMessage
    from app.models.chat_session import ChatSession
    from app.models.participant import Participant

    cfg = trigger.config or {}
    from_agent_name = cfg.get("from_agent_name")
    if not from_agent_name:
        return False

    since = trigger.last_fired_at or trigger.created_at

    try:
        async with async_session() as db:
            # Find the source agent and its participant
            from app.models.agent import Agent as AgentModel
            agent_r = await db.execute(
                select(AgentModel).where(AgentModel.name.ilike(f"%{from_agent_name}%"))
            )
            source_agent = agent_r.scalars().first()
            if not source_agent:
                return False

            # Find participant for the source agent
            result = await db.execute(
                select(Participant.id).where(
                    Participant.type == "agent",
                    Participant.ref_id == source_agent.id,
                )
            )
            from_participant = result.scalar_one_or_none()
            if not from_participant:
                return False

            # Check for new messages from this agent in shared sessions
            from sqlalchemy import cast as sa_cast, String as SaString
            result = await db.execute(
                select(ChatMessage).join(
                    ChatSession, ChatMessage.conversation_id == sa_cast(ChatSession.id, SaString)
                ).where(
                    ChatMessage.participant_id == from_participant,
                    ChatMessage.created_at > since,
                    ChatMessage.role == "assistant",  # agent replies
                ).order_by(ChatMessage.created_at.desc()).limit(1)
            )
            msg = result.scalar_one_or_none()
            if not msg:
                return False

            # Store matched message content for invocation context
            cfg["_matched_message"] = (msg.content or "")[:2000]
            cfg["_matched_from"] = from_agent_name
            return True

    except Exception as e:
        logger.warning(f"on_message check failed for trigger {trigger.name}: {e}")
        return False


# ── Agent Invocation ────────────────────────────────────────────────

async def _invoke_agent_for_triggers(agent_id: uuid.UUID, triggers: list[AgentTrigger]):
    """Invoke an agent with context from one or more fired triggers.

    Creates a Pulse Session (内心独白) and calls the LLM.
    """
    from app.api.websocket import call_llm
    from app.services.agent_context import build_agent_context
    from app.models.llm import LLMModel
    from app.models.audit import ChatMessage
    from app.models.chat_session import ChatSession
    from app.models.participant import Participant
    from app.services.audit_logger import write_audit_log

    try:
        async with async_session() as db:
            # Load agent
            result = await db.execute(select(Agent).where(Agent.id == agent_id))
            agent = result.scalar_one_or_none()
            if not agent or agent.is_expired:
                return

            # Load LLM model
            if not agent.primary_model_id:
                logger.warning(f"Agent {agent.name} has no LLM model, skipping trigger invocation")
                return
            result = await db.execute(select(LLMModel).where(LLMModel.id == agent.primary_model_id))
            model = result.scalar_one_or_none()
            if not model:
                return

            # Build trigger context
            context_parts = []
            trigger_names = []
            for t in triggers:
                part = f"触发器：{t.name} ({t.type})\n原因：{t.reason}"
                if t.agenda_ref:
                    part += f"\n关联 agenda：{t.agenda_ref}"
                # Include matched message for on_message triggers
                cfg = t.config or {}
                if t.type == "on_message" and cfg.get("_matched_message"):
                    part += f"\n收到来自 {cfg.get('_matched_from', '?')} 的消息：\n\"{cfg['_matched_message'][:500]}\""
                context_parts.append(part)
                trigger_names.append(t.name)

            trigger_context = (
                "===== 本次唤醒上下文 =====\n"
                f"唤醒来源：trigger（{'多个触发器同时触发' if len(triggers) > 1 else '触发器触发'}）\n\n"
                + "\n---\n".join(context_parts)
                + "\n==========================="
            )

            # Create Pulse Session (内心独白)
            title = f"🤖 内心独白：{', '.join(trigger_names)}"
            # Find agent's participant
            result = await db.execute(
                select(Participant).where(Participant.type == "agent", Participant.ref_id == agent_id)
            )
            agent_participant = result.scalar_one_or_none()

            session = ChatSession(
                agent_id=agent_id,
                user_id=agent.creator_id,
                participant_id=agent_participant.id if agent_participant else None,
                source_channel="trigger",
                title=title[:200],
            )
            db.add(session)
            await db.flush()
            session_id = session.id

            # Build system prompt
            system_prompt = await build_agent_context(agent_id, agent.name, agent.role_description or "")

            # Messages: system + trigger context
            messages = [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": trigger_context},
            ]

            # Store trigger context as a message in the session
            db.add(ChatMessage(
                agent_id=agent_id,
                conversation_id=str(session_id),
                role="user",
                content=trigger_context,
                user_id=agent.creator_id,
                participant_id=agent_participant.id if agent_participant else None,
            ))
            await db.commit()

        # Call LLM (outside the DB session to avoid long transactions)
        collected_content = []

        async def on_chunk(text):
            collected_content.append(text)

        reply = await call_llm(
            model=model,
            messages=messages,
            agent_name=agent.name,
            role_description=agent.role_description or "",
            agent_id=agent_id,
            user_id=agent.creator_id,
            on_chunk=on_chunk,
        )

        # Store the reply in the Pulse Session
        async with async_session() as db:
            result = await db.execute(
                select(Participant).where(Participant.type == "agent", Participant.ref_id == agent_id)
            )
            agent_participant = result.scalar_one_or_none()

            db.add(ChatMessage(
                agent_id=agent_id,
                conversation_id=str(session_id),
                role="assistant",
                content=reply or "".join(collected_content),
                user_id=agent.creator_id,
                participant_id=agent_participant.id if agent_participant else None,
            ))

            # Update trigger states
            for t in triggers:
                result = await db.execute(select(AgentTrigger).where(AgentTrigger.id == t.id))
                trigger = result.scalar_one_or_none()
                if trigger:
                    trigger.last_fired_at = datetime.now(timezone.utc)
                    trigger.fire_count += 1
                    # Auto-disable single-shot types
                    if trigger.type == "once":
                        trigger.is_enabled = False
                    if trigger.type == "on_message":
                        trigger.is_enabled = False  # single-shot for agent-to-agent
                    # Auto-disable expired
                    if trigger.max_fires and trigger.fire_count >= trigger.max_fires:
                        trigger.is_enabled = False

            await db.commit()

        # Push trigger result to user's active WebSocket connections
        final_reply = reply or "".join(collected_content)
        if final_reply:
            try:
                from app.api.websocket import manager as ws_manager
                agent_id_str = str(agent_id)

                # Build notification message with trigger badge
                trigger_badge = ", ".join(trigger_names)
                notification = f"⚡ **触发器触发** `{trigger_badge}`\n\n{final_reply}"

                # Save to user's most recent web chat session for persistence
                async with async_session() as db:
                    from app.models.chat_session import ChatSession
                    from sqlalchemy import func, case
                    _sr = await db.execute(
                        select(ChatSession)
                        .where(
                            ChatSession.agent_id == agent_id,
                            ChatSession.user_id == agent.creator_id,
                            ChatSession.source_channel.notin_(["trigger"]),
                        )
                        .order_by(
                            func.coalesce(ChatSession.last_message_at, ChatSession.created_at).desc()
                        )
                        .limit(1)
                    )
                    web_session = _sr.scalar_one_or_none()
                    if web_session:
                        logger.info(f"⚡ Saving trigger notification to web session {web_session.id} ({web_session.title})")
                        db.add(ChatMessage(
                            agent_id=agent_id,
                            conversation_id=str(web_session.id),
                            role="assistant",
                            content=notification,
                            user_id=agent.creator_id,
                        ))
                        await db.commit()
                        logger.info(f"⚡ Trigger notification saved to web session successfully")
                    else:
                        logger.warning(f"⚡ No web session found for agent {agent.name} (creator={agent.creator_id})")

                # Push to all active WebSocket connections for this agent
                if agent_id_str in ws_manager.active_connections:
                    for ws in list(ws_manager.active_connections[agent_id_str]):
                        try:
                            await ws.send_json({
                                "type": "trigger_notification",
                                "content": notification,
                                "triggers": [t.name for t in triggers],
                            })
                        except Exception:
                            pass  # Connection may have closed
            except Exception as e:
                logger.error(f"Failed to push trigger result to WebSocket: {e}")
                import traceback
                traceback.print_exc()

        # Audit log
        await write_audit_log("trigger_fired", {
            "agent_name": agent.name,
            "triggers": [{"name": t.name, "type": t.type} for t in triggers],
        }, agent_id=agent_id)

        logger.info(f"⚡ Triggers fired for {agent.name}: {[t.name for t in triggers]}")

    except Exception as e:
        logger.error(f"Failed to invoke agent {agent_id} for triggers: {e}")
        import traceback
        traceback.print_exc()


# ── Main Tick Loop ──────────────────────────────────────────────────

async def _tick():
    """One daemon tick: evaluate all triggers, group by agent, invoke."""
    now = datetime.now(timezone.utc)

    async with async_session() as db:
        result = await db.execute(
            select(AgentTrigger).where(AgentTrigger.is_enabled == True)
        )
        all_triggers = result.scalars().all()

    if not all_triggers:
        return


    # Evaluate and group fired triggers by agent
    fired_by_agent: dict[uuid.UUID, list[AgentTrigger]] = {}
    for trigger in all_triggers:
        # Auto-disable expired triggers
        if trigger.expires_at and now >= trigger.expires_at:
            async with async_session() as db:
                result = await db.execute(select(AgentTrigger).where(AgentTrigger.id == trigger.id))
                t = result.scalar_one_or_none()
                if t:
                    t.is_enabled = False
                    await db.commit()
            continue

        try:
            if await _evaluate_trigger(trigger, now):
                fired_by_agent.setdefault(trigger.agent_id, []).append(trigger)
        except Exception as e:
            logger.warning(f"Error evaluating trigger {trigger.name}: {e}")

    # Invoke each agent (with dedup window)
    for agent_id, agent_triggers in fired_by_agent.items():
        last = _last_invoke.get(agent_id)
        if last and (now - last).total_seconds() < DEDUP_WINDOW:
            continue  # Skip — invoked too recently
        _last_invoke[agent_id] = now
        asyncio.create_task(_invoke_agent_for_triggers(agent_id, agent_triggers))


async def start_trigger_daemon():
    """Start the background trigger daemon loop. Called from FastAPI startup."""
    logger.info("⚡ Trigger Daemon started (15s tick)")
    while True:
        try:
            await _tick()
        except Exception as e:
            logger.error(f"Trigger Daemon error: {e}")
            import traceback
            traceback.print_exc()
        await asyncio.sleep(TICK_INTERVAL)
