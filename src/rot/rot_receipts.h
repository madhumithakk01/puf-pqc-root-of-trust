#ifndef ROT_RECEIPTS_H
#define ROT_RECEIPTS_H

#include "rot/rot_journal.h"
#include "rot/rot_keys.h"
#include "rot/rot_platform.h"
#include "rot/rot_receipt.h"

/*
 * Receipt ring: the last ROT_RCP1_RING receipts, one per sector, receipt n at
 * sector ROT_SECTOR_RCP1_FIRST + n % ROT_RCP1_RING.
 */

enum { ROT_RCPS_OK = 0, ROT_RCPS_NONE = -1, ROT_RCPS_IO = -2, ROT_RCPS_SIGN = -3 };

/*
 * Build, sign and store the next receipt. `r` carries the outcome fields;
 * seq, device_id, prev_digest and journal_seq are filled here. On success the
 * journal's receipt_seq and last_receipt_digest are advanced in memory (the
 * caller commits the journal next). If a power cut falls between the two
 * writes, the ring holds a receipt the journal does not know; the next
 * attempt reuses the same sequence number and overwrites it.
 */
int rot_receipts_issue(const rot_platform *p, const rot_keys *k, rot_journal_t *j, rcp_t *r);

/* Read receipt `seq` (RCP_TOTAL_BYTES) if it is still in the ring. */
int rot_receipts_read(const rot_platform *p, uint32_t seq, uint8_t obj[RCP_TOTAL_BYTES]);

#endif
