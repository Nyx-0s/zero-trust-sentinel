#!/usr/bin/env python3
"""30-Day Win-Back Cron Job for Zero-Trust Sentinel.

Runs once a day. Finds customers who cancelled 30+ days ago and sends
the "Lifecycle" win-back email (not a "Scare" email). Uses a 30-day
silence period before re-engaging, per lifecycle-email best practice.

Run daily via cron:
    0 10 * * *  cd /app && python3 win_back_cron.py
"""

import asyncio
import logging
import os

from db import get_pool, mark_stage_sent
from api import send_win_back_email

# Configure logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger(__name__)

WIN_BACK_BATCH_LIMIT = 10
# Jitter between win-back sends (0 in simulation via WIN_BACK_JITTER_SECONDS)
WIN_BACK_JITTER_SECONDS = int(os.getenv("WIN_BACK_JITTER_SECONDS", "60"))


async def run_win_back_cron():
    """Sends win-back emails to customers who cancelled 30+ days ago."""
    logger.info("[CRON] Starting Win-Back Cron...")

    pool = await get_pool()
    async with pool.acquire() as conn:
        # Find cancelled customers from 30+ days ago who haven't been win-backed yet
        rows = await conn.fetch(
            """
            SELECT c.id FROM clients c
            JOIN subscriptions s ON c.id = s.client_id
            WHERE s.status = 'cancelled'
            AND s.cancelled_at < NOW() - INTERVAL '30 days'
            AND NOT EXISTS (
                SELECT 1 FROM lead_stages ls
                WHERE ls.lead_id = c.id AND ls.stage = 'win_back'
            )
            LIMIT $1
            """,
            WIN_BACK_BATCH_LIMIT,
        )
        customer_ids = [row["id"] for row in rows]

    sent = 0
    for customer_id in customer_ids:
        try:
            # Only a provider-accepted send is marked. A rejected/failed
            # send stays unmarked so the next daily tick can retry it
            # (still bounded by the NOT EXISTS stage filter above).
            accepted = await send_win_back_email(customer_id)
            if accepted:
                await mark_stage_sent(customer_id, "win_back")
                sent += 1
            else:
                logger.warning(
                    f"[CRON] Win-back not accepted for client {customer_id}; "
                    "stage left unmarked for a later retry")
        except Exception as e:
            logger.error(f"[CRON] Win-back failed for client {customer_id}: {e}")
        await asyncio.sleep(WIN_BACK_JITTER_SECONDS)  # Jitter between sends

    logger.info(f"[CRON] Win-Back Cron complete. Sent {sent} emails.")


if __name__ == "__main__":
    asyncio.run(run_win_back_cron())
