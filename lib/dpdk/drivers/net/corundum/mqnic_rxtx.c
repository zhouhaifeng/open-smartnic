/* SPDX-License-Identifier: BSD-3-Clause
 *
 * Copyright (c) 2023 Xinyu Yang.
 * Copyright (c) 2022 Bruce.
 */

#include "mqnic.h"


/*********************************************************************
 *
 *  TX function
 *
 **********************************************************************/

static void 
mqnic_deactivate_tx_queue(struct mqnic_tx_queue *txq)
{
    // deactivate queue
	MQNIC_DIRECT_WRITE_REG(txq->hw_addr, MQNIC_QUEUE_ACTIVE_LOG_SIZE_REG, ilog2(txq->size) | (txq->log_desc_block_size << 8));
}

static void 
mqnic_deactivate_rx_queue(struct mqnic_rx_queue *rxq)
{
	// deactivate queue
	MQNIC_DIRECT_WRITE_REG(rxq->hw_addr, MQNIC_QUEUE_ACTIVE_LOG_SIZE_REG, ilog2(rxq->size) | (rxq->log_desc_block_size << 8));
}

static int
mqnic_activate_rxq(struct mqnic_rx_queue *rxq, int cpl_index)
{
	rxq->cpl_index = cpl_index;
	// deactivate queue
	MQNIC_DIRECT_WRITE_REG(rxq->hw_addr, MQNIC_QUEUE_ACTIVE_LOG_SIZE_REG, 0);
	// set base address
	MQNIC_DIRECT_WRITE_REG(rxq->hw_addr, MQNIC_QUEUE_BASE_ADDR_REG+0, rxq->rx_ring_phys_addr);
	MQNIC_DIRECT_WRITE_REG(rxq->hw_addr, MQNIC_QUEUE_BASE_ADDR_REG+4, rxq->rx_ring_phys_addr >> 32);
	// set completion queue index
	MQNIC_DIRECT_WRITE_REG(rxq->hw_addr, MQNIC_QUEUE_CPL_QUEUE_INDEX_REG, rxq->cpl_index);
	// set pointers
	MQNIC_DIRECT_WRITE_REG(rxq->hw_addr, MQNIC_QUEUE_HEAD_PTR_REG, rxq->head_ptr & rxq->hw_ptr_mask);
	MQNIC_DIRECT_WRITE_REG(rxq->hw_addr, MQNIC_QUEUE_TAIL_PTR_REG, rxq->tail_ptr & rxq->hw_ptr_mask);
	// set size and activate queue
	MQNIC_DIRECT_WRITE_REG(rxq->hw_addr, MQNIC_QUEUE_ACTIVE_LOG_SIZE_REG, ilog2(rxq->size) | (rxq->log_desc_block_size << 8) | MQNIC_QUEUE_ACTIVE_MASK);
    return 0;
}

static bool 
mqnic_is_tx_queue_full(const struct mqnic_tx_queue *txq)
{
    return txq->head_ptr - txq->clean_tail_ptr >= txq->full_size;
}

static void 
mqnic_tx_read_tail_ptr(struct mqnic_tx_queue *txq)
{
    txq->tail_ptr += (MQNIC_DIRECT_READ_REG(txq->hw_tail_ptr, 0) - txq->tail_ptr) & txq->hw_ptr_mask;
	PMD_TX_LOG(DEBUG, "get txq->tail_ptr = %d", txq->tail_ptr);
}

static void 
mqnic_cq_read_head_ptr(struct mqnic_cq_ring *ring)
{
    ring->head_ptr += (MQNIC_DIRECT_READ_REG(ring->hw_head_ptr, 0) - ring->head_ptr) & ring->hw_ptr_mask;
	PMD_TX_LOG(DEBUG, "get cq ring->head_ptr = %d", ring->head_ptr);
}

static void 
mqnic_rx_cq_write_tail_ptr(struct mqnic_cq_ring *ring)
{
	MQNIC_DIRECT_WRITE_REG(ring->hw_tail_ptr, 0, ring->tail_ptr & ring->hw_ptr_mask);
	PMD_RX_LOG(DEBUG, "update cq ring tail ptr register = %d, ring->tail_ptr = %d", ring->tail_ptr & ring->hw_ptr_mask, ring->tail_ptr);
}

static void 
mqnic_tx_cq_write_tail_ptr(struct mqnic_cq_ring *ring)
{
	MQNIC_DIRECT_WRITE_REG(ring->hw_tail_ptr, 0, ring->tail_ptr & ring->hw_ptr_mask);
	PMD_TX_LOG(DEBUG, "update cq ring tail ptr register = %d, ring->tail_ptr = %d", ring->tail_ptr & ring->hw_ptr_mask, ring->tail_ptr);
}

static void 
mqnic_rx_read_tail_ptr(struct mqnic_rx_queue *rxq)
{
    rxq->tail_ptr += (MQNIC_DIRECT_READ_REG(rxq->hw_tail_ptr, 0) - rxq->tail_ptr) & rxq->hw_ptr_mask;
}

static void 
mqnic_rx_write_head_ptr(struct mqnic_rx_queue *rxq)
{
	MQNIC_DIRECT_WRITE_REG(rxq->hw_head_ptr, 0, rxq->head_ptr & rxq->hw_ptr_mask);
}

static inline void
mqnic_check_tx_cpl(struct mqnic_tx_queue *txq)
{
	struct mqnic_priv *priv = txq->priv;
	struct mqnic_cq_ring *cq_ring;

	PMD_TX_LOG(DEBUG, "mqnic_check_tx_cpl start");

	cq_ring = priv->tx_cpl_ring[txq->queue_id];   //assume queue_id of txq == queue_id of tx_cpl_queue
	mqnic_cq_read_head_ptr(cq_ring);

	cq_ring->tail_ptr = cq_ring->head_ptr;
    mqnic_tx_cq_write_tail_ptr(cq_ring);

    // process ring
    mqnic_tx_read_tail_ptr(txq);
	txq->clean_tail_ptr = txq->tail_ptr;

	mqnic_arm_cq(cq_ring);
	PMD_TX_LOG(DEBUG, "mqnic_check_tx_cpl finish");
}

uint16_t
eth_mqnic_xmit_pkts(void *tx_queue, struct rte_mbuf **tx_pkts,
	       uint16_t nb_pkts)
{
	struct mqnic_tx_queue *txq;
	struct mqnic_tx_entry *sw_ring;
	struct mqnic_tx_entry *txe, *txn;
	volatile struct mqnic_desc *txr;
	volatile struct mqnic_desc *txd;
	struct rte_mbuf     *tx_pkt;
	struct rte_mbuf     *m_seg;
	uint64_t buf_dma_addr;
	uint16_t slen;
	uint16_t tx_end;
	uint16_t tx_id;
	uint16_t tx_last;
	uint16_t nb_tx;
	uint32_t i;
	uint32_t sub_desc_index;
	struct mqnic_priv *priv;

	txq = tx_queue;
	priv= txq->priv;
	sw_ring = txq->sw_ring;
	txr     = txq->tx_ring;
	tx_id   = txq->tx_tail;
	txe = &sw_ring[tx_id];

	mqnic_check_tx_cpl(txq);

	for (nb_tx = 0; nb_tx < nb_pkts; nb_tx++) {
		sub_desc_index = 0;
		tx_pkt = *tx_pkts++;

		RTE_MBUF_PREFETCH_TO_FREE(txe->mbuf[0]);

		//tx_last = (uint16_t) (tx_id + tx_pkt->nb_segs - 1);
		tx_last = (uint16_t) tx_id;

		if (tx_last >= txq->nb_tx_desc)
			tx_last = (uint16_t) (tx_last - txq->nb_tx_desc);

		tx_end = sw_ring[tx_last].last_id;
		tx_end = sw_ring[tx_end].next_id;
		tx_end = sw_ring[tx_end].last_id;

		if(mqnic_is_tx_queue_full(txq)){
			PMD_TX_LOG(DEBUG, "mqnic_is_tx_queue_full");
			if (nb_tx == 0)
				return 0;
			goto end_of_tx;
		}

		m_seg = tx_pkt;
#if 0
		do {
			txn = &sw_ring[txe->next_id];
			txd = &txr[tx_id*4];

			if (txe->mbuf != NULL)
				rte_pktmbuf_free_seg(txe->mbuf);
			txe->mbuf = m_seg;

			/*
			 * Set up transmit descriptor.
			 */
			slen = (uint16_t) m_seg->data_len;
			buf_dma_addr = rte_mbuf_data_iova(m_seg);
			txd->addr =
				rte_cpu_to_le_64(buf_dma_addr);
			txd->len =
				rte_cpu_to_le_32(slen);

    		for (i = 0; i < txq->desc_block_size-1; i++)
    		{
       			txd[i+1].len = 0;
        		txd[i+1].addr = 0;
    		}

			txq->head_ptr++;
			txe->last_id = tx_last;
			tx_id = txe->next_id;
			txe = txn;
			m_seg = m_seg->next;
			priv->opackets++;
			priv->obytes+=slen;
		} while (m_seg != NULL);
#endif
		txn = &sw_ring[txe->next_id];
		do {
			txd = &txr[tx_id*4+sub_desc_index];

			if (txe->mbuf[sub_desc_index] != NULL)
				rte_pktmbuf_free_seg(txe->mbuf[sub_desc_index]);
			txe->mbuf[sub_desc_index] = m_seg;

			/*
			 * Set up transmit descriptor.
			 */
			slen = (uint16_t) m_seg->data_len;
			buf_dma_addr = rte_mbuf_data_iova(m_seg);
			txd->addr =
				rte_cpu_to_le_64(buf_dma_addr);
			txd->len =
				rte_cpu_to_le_32(slen);
			
			m_seg = m_seg->next;
			priv->obytes+=slen;
			sub_desc_index++;
			if(sub_desc_index >= txq->desc_block_size)
				break;
		} while (m_seg != NULL);

		for (i = sub_desc_index; i < 4; i++)
    	{
       		txd[i].len = 0;
        	txd[i].addr = 0;
    	}
		txe->last_id = tx_last;
		tx_id = txe->next_id;
		txe = txn;
		txq->head_ptr++;
		priv->opackets++;
	}
 end_of_tx:
	rte_wmb();

	MQNIC_DIRECT_WRITE_REG(txq->hw_head_ptr, 0, txq->head_ptr & txq->hw_ptr_mask);
	PMD_TX_LOG(DEBUG, "port_id=%u queue_id=%u tx_tail=%u nb_tx=%u txq->head_ptr=%u",
		   (unsigned) txq->port_id, (unsigned) txq->queue_id,
		   (unsigned) tx_id, (unsigned) nb_tx, (unsigned) txq->head_ptr);
	txq->tx_tail = tx_id;

	return nb_tx;
}

/*********************************************************************
 *
 *  RX functions
 *
 **********************************************************************/
uint16_t
eth_mqnic_recv_pkts(void *rx_queue, struct rte_mbuf **rx_pkts,
	       uint16_t nb_pkts)
{
	struct mqnic_rx_queue *rxq;
	volatile struct mqnic_desc *rx_ring;
	volatile struct mqnic_desc *rxdp;
	struct mqnic_rx_entry *sw_ring;
	struct mqnic_rx_entry *rxe;
	struct rte_mbuf *rxm;
	struct rte_mbuf *nmb;
	uint64_t dma_addr;
	uint16_t pkt_len;
	uint16_t rx_id;
	uint16_t nb_rx;
	uint16_t nb_hold;
	uint32_t cq_index;
	uint32_t cq_tail_ptr;
	uint32_t cq_desc_inline_index;
	uint32_t ring_clean_tail_ptr;
	volatile struct mqnic_cpl *cpl;
	struct mqnic_cq_ring *cq_ring;
	struct mqnic_priv *priv;
	int done = 0;
    int budget;

	rxq = rx_queue;
	budget = rxq->full_size;
	priv = rxq->priv;
	cq_ring = priv->rx_cpl_ring[rxq->queue_id];
	mqnic_cq_read_head_ptr(cq_ring);

    cq_tail_ptr = cq_ring->tail_ptr;
    cq_index = cq_tail_ptr & cq_ring->size_mask;

	nb_rx = 0;
	nb_hold = 0;
	rx_id = rxq->rx_tail;
	rx_ring = rxq->rx_ring;
	sw_ring = rxq->sw_ring;

	if(cq_ring->ring_index != rxq->queue_id)
		PMD_RX_LOG(ERR, "wrong cq_ring->ring_index, %d != %d", cq_ring->ring_index, rxq->queue_id);

	while ((nb_rx < nb_pkts) && (cq_ring->head_ptr != cq_tail_ptr) && (done < budget)) {
		cpl = (volatile struct mqnic_cpl *)(cq_ring->buf + cq_index*cq_ring->stride);
		cq_desc_inline_index = cpl->index & rxq->size_mask; //number of desc

		PMD_RX_LOG(DEBUG, "eth_mqnic_recv_pkts, nb_pkts = %d, cq_ring->head_ptr = %d, cq_tail_ptr = %d, budget = %d, cpl->len = %d",
			nb_pkts, cq_ring->head_ptr, cq_tail_ptr, budget, cpl->len);
		if(cq_desc_inline_index != cq_index){
			PMD_RX_LOG(ERR, "wrong cq desc index, %d != %d", cq_desc_inline_index, cq_index);
			break;
		}

		if(rx_id != cq_index){
			PMD_RX_LOG(ERR, "wrong rx_id, %d != %d", rx_id, cq_index);
			break;
		}
		rxdp = &rx_ring[rx_id];

		PMD_RX_LOG(DEBUG, "port_id=%u queue_id=%u rx_id=%u ",
			   (unsigned) rxq->port_id, (unsigned) rxq->queue_id,
			   (unsigned) rx_id);

		nmb = rte_mbuf_raw_alloc(rxq->mb_pool);
		if (nmb == NULL) {
			PMD_RX_LOG(ERR, "RX mbuf alloc failed port_id=%u "
				   "queue_id=%u", (unsigned) rxq->port_id,
				   (unsigned) rxq->queue_id);
			rte_eth_devices[rxq->port_id].data->rx_mbuf_alloc_failed++;
			break;
		}

		nb_hold++;
		rxe = &sw_ring[rx_id];
		rx_id++;
		if (rx_id == rxq->nb_rx_desc)
			rx_id = 0;

		/* Prefetch next mbuf while processing current one. */
		rte_mqnic_prefetch(sw_ring[rx_id].mbuf);

		/*
		 * When next RX descriptor is on a cache-line boundary,
		 * prefetch the next 4 RX descriptors and the next 8 pointers
		 * to mbufs.
		 */
		if ((rx_id & 0x3) == 0) {
			rte_mqnic_prefetch(&rx_ring[rx_id]);
			rte_mqnic_prefetch(&sw_ring[rx_id]);
		}

		rxm = rxe->mbuf;
		rxe->mbuf = nmb;
		dma_addr =
			rte_cpu_to_le_64(rte_mbuf_data_iova_default(nmb));
		rxdp->len = nmb->buf_len;
		PMD_RX_LOG(DEBUG, "nmb->buf_len=%u ", (unsigned) nmb->buf_len);
		rxdp->addr = dma_addr;

		rxq->head_ptr++;

		/*
		 * Initialize the returned mbuf.
		 * 1) setup generic mbuf fields:
		 *    - number of segments,
		 *    - next segment,
		 *    - packet length,
		 *    - RX port identifier.
		 * 2) integrate hardware offload data, if any:
		 *    - RSS flag & hash,
		 *    - IP checksum flag,
		 *    - VLAN TCI, if any,
		 *    - error flags.
		 */
		pkt_len = (uint16_t)cpl->len;
		rxm->data_off = RTE_PKTMBUF_HEADROOM;
		rte_packet_prefetch((char *)rxm->buf_addr + rxm->data_off);
		rxm->nb_segs = 1;
		rxm->next = NULL;
		rxm->pkt_len = pkt_len;
		rxm->data_len = pkt_len;
		rxm->port = rxq->port_id;

		/*
		 * Store the mbuf address into the next entry of the array
		 * of returned packets.
		 */
		rx_pkts[nb_rx++] = rxm;
		done++;
		cq_tail_ptr++;
        cq_index = cq_tail_ptr & cq_ring->size_mask;

		priv->ipackets++;
		priv->ibytes+=pkt_len;
	}
	rxq->rx_tail = rx_id;

	// update CQ tail
    cq_ring->tail_ptr = cq_tail_ptr;
    mqnic_rx_cq_write_tail_ptr(cq_ring);

	mqnic_rx_read_tail_ptr(rxq);

    ring_clean_tail_ptr = rxq->clean_tail_ptr;

    while (ring_clean_tail_ptr != rxq->tail_ptr)
    {
        ring_clean_tail_ptr++;
    }

    // update ring tail
    rxq->clean_tail_ptr = ring_clean_tail_ptr;

	mqnic_rx_write_head_ptr(rxq);
	MQNIC_WRITE_FLUSH(priv);
	mqnic_arm_cq(cq_ring);

	return nb_rx;
}

uint16_t
eth_mqnic_recv_scattered_pkts(void *rx_queue, struct rte_mbuf **rx_pkts,
			 uint16_t nb_pkts)
{
	RTE_SET_USED(rx_queue);
	RTE_SET_USED(rx_pkts);
	RTE_SET_USED(nb_pkts);
	PMD_RX_LOG(ERR, "eth_mqnic_recv_scattered_pkts is not supported");
	return 0;

}

/*
 * Maximum number of Ring Descriptors.
 *
 * Since RDLEN/TDLEN should be multiple of 128bytes, the number of ring
 * desscriptors should meet the following condition:
 *      (num_ring_desc * sizeof(struct mqnic_rx/tx_desc)) % 128 == 0
 */

static void
mqnic_tx_queue_release_mbufs(struct mqnic_tx_queue *txq)
{
	unsigned i, j;

	if (txq->sw_ring != NULL) {
		for (i = 0; i < txq->nb_tx_desc; i++) {
			for(j = 0; j < DESC_BLOCK_SIZE; j++){
				if (txq->sw_ring[i].mbuf[j] != NULL) {
					rte_pktmbuf_free_seg(txq->sw_ring[i].mbuf[j]);
					txq->sw_ring[i].mbuf[j] = NULL;
				}
			}
		}
	}
}

static void
mqnic_tx_queue_release(struct mqnic_tx_queue *txq)
{
	if (txq != NULL) {
		mqnic_tx_queue_release_mbufs(txq);
		rte_free(txq->sw_ring);
		rte_free(txq);
	}
}

void
mqnic_cpl_queue_release(struct mqnic_cq_ring *ring)
{
	if (ring != NULL) {
		rte_free(ring);
	}
}

void
eth_mqnic_tx_queue_release(void *txq)
{
	mqnic_tx_queue_release(txq);
}

static int
mqnic_tx_done_cleanup(struct mqnic_tx_queue *txq, uint32_t free_cnt)
{
	struct mqnic_tx_entry *sw_ring;
	uint16_t tx_first; /* First segment analyzed. */
	uint16_t tx_id;    /* Current segment being processed. */
	uint16_t tx_last;  /* Last segment in the current packet. */
	uint16_t tx_next;  /* First segment of the next packet. */
	int count = 0;
	int i = 0;
	PMD_TX_LOG(DEBUG, "mqnic_tx_done_cleanup");

	if (!txq)
		return -ENODEV;

	sw_ring = txq->sw_ring;

	/* tx_tail is the last sent packet on the sw_ring. Goto the end
	 * of that packet (the last segment in the packet chain) and
	 * then the next segment will be the start of the oldest segment
	 * in the sw_ring. This is the first packet that will be
	 * attempted to be freed.
	 */

	/* Get last segment in most recently added packet. */
	tx_first = sw_ring[txq->tx_tail].last_id;

	/* Get the next segment, which is the oldest segment in ring. */
	tx_first = sw_ring[tx_first].next_id;

	/* Set the current index to the first. */
	tx_id = tx_first;

	/* Loop through each packet. For each packet, verify that an
	 * mbuf exists and that the last segment is free. If so, free
	 * it and move on.
	 */
	mqnic_check_tx_cpl(txq);
	while (1) {
		tx_last = sw_ring[tx_id].last_id;

		if (sw_ring[tx_last].mbuf[0]) {
			//if (txr[tx_last].wb.status &
			//    MQNIC_TXD_STAT_DD) {
			if(1){
				/* Increment the number of packets
				 * freed.
				 */
				count++;

				/* Get the start of the next packet. */
				tx_next = sw_ring[tx_last].next_id;

				/* Loop through all segments in a
				 * packet.
				 */
				do {
					for(i = 0; i < DESC_BLOCK_SIZE; i++){
						if (sw_ring[tx_id].mbuf[i]) {
							rte_pktmbuf_free_seg(
								sw_ring[tx_id].mbuf[i]);
							sw_ring[tx_id].mbuf[i] = NULL;
							if(i == 0)
								sw_ring[tx_id].last_id = tx_id;
						}
					}

					/* Move to next segemnt. */
					tx_id = sw_ring[tx_id].next_id;

				} while (tx_id != tx_next);

				if (unlikely(count == (int)free_cnt))
					break;
			} else {
				/* mbuf still in use, nothing left to
				 * free.
				 */
				break;
			}
		} else {
			/* There are multiple reasons to be here:
			 * 1) All the packets on the ring have been
			 *    freed - tx_id is equal to tx_first
			 *    and some packets have been freed.
			 *    - Done, exit
			 * 2) Interfaces has not sent a rings worth of
			 *    packets yet, so the segment after tail is
			 *    still empty. Or a previous call to this
			 *    function freed some of the segments but
			 *    not all so there is a hole in the list.
			 *    Hopefully this is a rare case.
			 *    - Walk the list and find the next mbuf. If
			 *      there isn't one, then done.
			 */
			if (likely(tx_id == tx_first && count != 0))
				break;

			/* Walk the list and find the next mbuf, if any. */
			do {
				/* Move to next segemnt. */
				tx_id = sw_ring[tx_id].next_id;

				if (sw_ring[tx_id].mbuf[0])
					break;

			} while (tx_id != tx_first);

			/* Determine why previous loop bailed. If there
			 * is not an mbuf, done.
			 */
			if (!sw_ring[tx_id].mbuf[0])
				break;
		}
	}

	return count;
}

int
eth_mqnic_tx_done_cleanup(void *txq, uint32_t free_cnt)
{
	return mqnic_tx_done_cleanup(txq, free_cnt);
}

static void
mqnic_reset_tx_queue_stat(struct mqnic_tx_queue *txq)
{
	txq->tx_head = 0;
	txq->tx_tail = 0;
	txq->ctx_curr = 0;
	txq->head_ptr = 0;
    txq->tail_ptr = 0;
    txq->clean_tail_ptr = 0;
}

static void
mqnic_reset_tx_queue(struct mqnic_tx_queue *txq, struct rte_eth_dev *dev)
{
	static const struct mqnic_desc zeroed_desc = {0, 0, 0, 0};
	struct mqnic_tx_entry *txe = txq->sw_ring;
	uint16_t i, j, prev;
	RTE_SET_USED(dev);

	/* Zero out HW ring memory */
	for (i = 0; i < txq->nb_tx_desc*DESC_BLOCK_SIZE; i++) {
		txq->tx_ring[i] = zeroed_desc;
	}

	/* Initialize ring entries */
	prev = (uint16_t)(txq->nb_tx_desc - 1);
	for (i = 0; i < txq->nb_tx_desc; i++) {
		for(j = 0; j < DESC_BLOCK_SIZE; j++){
			txe[i].mbuf[j] = NULL;
		}
		txe[i].last_id = i;
		txe[prev].next_id = i;
		prev = i;
	}

	mqnic_reset_tx_queue_stat(txq);
}

uint64_t
mqnic_get_tx_port_offloads_capa(struct rte_eth_dev *dev)
{
	uint64_t tx_offload_capa = 0;

	RTE_SET_USED(dev);
#if 0
	tx_offload_capa = DEV_TX_OFFLOAD_VLAN_INSERT |
			  DEV_TX_OFFLOAD_IPV4_CKSUM  |
			  DEV_TX_OFFLOAD_UDP_CKSUM   |
			  DEV_TX_OFFLOAD_TCP_CKSUM   |
			  DEV_TX_OFFLOAD_SCTP_CKSUM  |
			  DEV_TX_OFFLOAD_TCP_TSO     |
			  DEV_TX_OFFLOAD_MULTI_SEGS;
#endif
	return tx_offload_capa;
}

uint64_t
mqnic_get_tx_queue_offloads_capa(struct rte_eth_dev *dev)
{
	uint64_t tx_queue_offload_capa;

	tx_queue_offload_capa = mqnic_get_tx_port_offloads_capa(dev);

	return tx_queue_offload_capa;
}

int
eth_mqnic_tx_queue_setup(struct rte_eth_dev *dev,
			 uint16_t queue_idx,
			 uint16_t nb_desc,
			 unsigned int socket_id,
			 const struct rte_eth_txconf *tx_conf)
{
	const struct rte_memzone *tz;
	struct mqnic_tx_queue *txq;
	uint64_t offloads;
	struct mqnic_priv *priv =
		MQNIC_DEV_PRIVATE_TO_PRIV(dev->data->dev_private);

	offloads = tx_conf->offloads | dev->data->dev_conf.txmode.offloads;

	/*
	 * Validate number of transmit descriptors.
	 * It must not exceed hardware maximum, and must be multiple
	 * of MQNIC_ALIGN.
	 */
	if (nb_desc % IGB_TXD_ALIGN != 0 ||
			(nb_desc > MQNIC_MAX_RING_DESC) ||
			(nb_desc < MQNIC_MIN_RING_DESC)) {
			PMD_INIT_LOG(INFO, "nb_desc(%d) must > %d and < %d.",
				nb_desc, MQNIC_MIN_RING_DESC, MQNIC_MAX_RING_DESC);
		return -EINVAL;
	}

	/* Free memory prior to re-allocation if needed */
	if (dev->data->tx_queues[queue_idx] != NULL) {
		mqnic_tx_queue_release(dev->data->tx_queues[queue_idx]);
		dev->data->tx_queues[queue_idx] = NULL;
	}

	/* First allocate the tx queue data structure */
	txq = rte_zmalloc("ethdev TX queue", sizeof(struct mqnic_tx_queue),
							RTE_CACHE_LINE_SIZE);
	if (txq == NULL)
		return -ENOMEM;

	txq->size = roundup_pow_of_two(nb_desc);
    txq->full_size = txq->size >> 1;
    txq->size_mask = txq->size-1;
    txq->stride = roundup_pow_of_two(MQNIC_DESC_SIZE*priv->desc_block_size);

    txq->desc_block_size = txq->stride/MQNIC_DESC_SIZE;
    txq->log_desc_block_size = txq->desc_block_size < 2 ? 0 : ilog2(txq->desc_block_size-1)+1;
    txq->desc_block_size = 1 << txq->log_desc_block_size;

	txq->buf_size = txq->size*txq->stride;

	/*
	 * Allocate TX ring hardware descriptors. A memzone large enough to
	 * handle the maximum ring size is allocated in order to allow for
	 * resizing in later calls to the queue setup function.
	 */
	tz = rte_eth_dma_zone_reserve(dev, "tx_ring", queue_idx, txq->buf_size,
				      MQNIC_ALIGN, socket_id);
	if (tz == NULL) {
		mqnic_tx_queue_release(txq);
		return -ENOMEM;
	}

	txq->nb_tx_desc = txq->size;
	txq->queue_id = queue_idx;
	txq->reg_idx = queue_idx;
	txq->port_id = dev->data->port_id;
	txq->tx_ring_phys_addr = tz->iova;
	txq->tx_ring = (struct mqnic_desc *) tz->addr;

	txq->sw_ring = rte_zmalloc("txq->sw_ring",
				   sizeof(struct mqnic_tx_entry) * txq->nb_tx_desc,
				   RTE_CACHE_LINE_SIZE);
	if (txq->sw_ring == NULL) {
		PMD_INIT_LOG(ERR, "failed to alloc sw_ring");
		mqnic_tx_queue_release(txq);
		return -ENOMEM;
	}
	PMD_INIT_LOG(DEBUG, "tx sw_ring=%p hw_ring=%p dma_addr=0x%"PRIx64,
		     txq->sw_ring, txq->tx_ring, txq->tx_ring_phys_addr);

	txq->hw_addr = priv->hw_addr+priv->tx_queue_offset+queue_idx*MQNIC_QUEUE_STRIDE;
    txq->hw_ptr_mask = 0xffff;
    txq->hw_head_ptr = txq->hw_addr+MQNIC_QUEUE_HEAD_PTR_REG;
    txq->hw_tail_ptr = txq->hw_addr+MQNIC_QUEUE_TAIL_PTR_REG;
	txq->head_ptr = 0;
    txq->tail_ptr = 0;
    txq->clean_tail_ptr = 0;

	mqnic_reset_tx_queue(txq, dev);

	dev->data->tx_queues[queue_idx] = txq;
	txq->offloads = offloads;

	return 0;
}

static void
mqnic_rx_queue_release_mbufs(struct mqnic_rx_queue *rxq)
{
	unsigned i;

	if (rxq->sw_ring != NULL) {
		for (i = 0; i < rxq->nb_rx_desc; i++) {
			if (rxq->sw_ring[i].mbuf != NULL) {
				rte_pktmbuf_free_seg(rxq->sw_ring[i].mbuf);
				rxq->sw_ring[i].mbuf = NULL;
			}
		}
	}
}

static void
mqnic_rx_queue_release(struct mqnic_rx_queue *rxq)
{
	if (rxq != NULL) {
		mqnic_rx_queue_release_mbufs(rxq);
		rte_free(rxq->sw_ring);
		rte_free(rxq);
	}
}

void
eth_mqnic_rx_queue_release(void *rxq)
{
	mqnic_rx_queue_release(rxq);
}

static void
mqnic_reset_rx_queue(struct mqnic_rx_queue *rxq)
{
	//static const union mqnic_adv_rx_desc zeroed_desc = {{0}};
	static const struct mqnic_desc zeroed_desc = {0, 0, 0, 0};
	unsigned i;

	/* Zero out HW ring memory */
	for (i = 0; i < rxq->nb_rx_desc; i++) {
		rxq->rx_ring[i] = zeroed_desc;
	}

	rxq->rx_tail = 0;
	rxq->pkt_first_seg = NULL;
	rxq->pkt_last_seg = NULL;

	rxq->head_ptr = 0;
    rxq->tail_ptr = 0;
    rxq->clean_tail_ptr = 0;
}

uint64_t
mqnic_get_rx_port_offloads_capa(struct rte_eth_dev *dev)
{
	uint64_t rx_offload_capa = 0;
	RTE_SET_USED(dev);

	return rx_offload_capa;
}

uint64_t
mqnic_get_rx_queue_offloads_capa(struct rte_eth_dev *dev)
{
	uint64_t rx_queue_offload_capa;
	RTE_SET_USED(dev);
	rx_queue_offload_capa = 0;

	return rx_queue_offload_capa;
}

int
eth_mqnic_rx_queue_setup(struct rte_eth_dev *dev,
			 uint16_t queue_idx,
			 uint16_t nb_desc,
			 unsigned int socket_id,
			 const struct rte_eth_rxconf *rx_conf,
			 struct rte_mempool *mp)
{
	const struct rte_memzone *rz;
	struct mqnic_rx_queue *rxq;
	uint64_t offloads;
	struct mqnic_priv *priv =
		MQNIC_DEV_PRIVATE_TO_PRIV(dev->data->dev_private);

	offloads = rx_conf->offloads | dev->data->dev_conf.rxmode.offloads;

	/*
	 * Validate number of receive descriptors.
	 * It must not exceed hardware maximum, and must be multiple
	 * of MQNIC_ALIGN.
	 */
	if (nb_desc % IGB_RXD_ALIGN != 0 ||
			(nb_desc > MQNIC_MAX_RING_DESC) ||
			(nb_desc < MQNIC_MIN_RING_DESC)) {
			PMD_INIT_LOG(INFO, "nb_desc(%d) must > %d and < %d.",
				nb_desc, MQNIC_MIN_RING_DESC, MQNIC_MAX_RING_DESC);
		return -EINVAL;
	}

	/* Free memory prior to re-allocation if needed */
	if (dev->data->rx_queues[queue_idx] != NULL) {
		mqnic_rx_queue_release(dev->data->rx_queues[queue_idx]);
		dev->data->rx_queues[queue_idx] = NULL;
	}

	/* First allocate the RX queue data structure. */
	rxq = rte_zmalloc("ethdev RX queue", sizeof(struct mqnic_rx_queue),
			  RTE_CACHE_LINE_SIZE);
	if (rxq == NULL)
		return -ENOMEM;

	rxq->size = roundup_pow_of_two(nb_desc);
	rxq->full_size = rxq->size >> 1;
    rxq->size_mask = rxq->size-1;
    rxq->stride = roundup_pow_of_two(MQNIC_DESC_SIZE);

    rxq->desc_block_size = rxq->stride/MQNIC_DESC_SIZE;
    rxq->log_desc_block_size = rxq->desc_block_size < 2 ? 0 : ilog2(rxq->desc_block_size-1)+1;
    rxq->desc_block_size = 1 << rxq->log_desc_block_size;

	rxq->buf_size = rxq->size*rxq->stride;

	rxq->offloads = offloads;
	rxq->mb_pool = mp;
	rxq->nb_rx_desc = rxq->size;

	rxq->drop_en = rx_conf->rx_drop_en;
	rxq->rx_free_thresh = rx_conf->rx_free_thresh;
	rxq->queue_id = queue_idx;
	rxq->reg_idx = queue_idx;
	rxq->port_id = dev->data->port_id;
	if (dev->data->dev_conf.rxmode.offloads & DEV_RX_OFFLOAD_KEEP_CRC)
		rxq->crc_len = RTE_ETHER_CRC_LEN;
	else
		rxq->crc_len = 0;

	/*
	 *  Allocate RX ring hardware descriptors. A memzone large enough to
	 *  handle the maximum ring size is allocated in order to allow for
	 *  resizing in later calls to the queue setup function.
	 */
	rz = rte_eth_dma_zone_reserve(dev, "rx_ring", queue_idx, rxq->buf_size,
				      MQNIC_ALIGN, socket_id);
	if (rz == NULL) {
		mqnic_rx_queue_release(rxq);
		return -ENOMEM;
	}

	rxq->hw_addr = priv->hw_addr+priv->rx_queue_offset+queue_idx*MQNIC_QUEUE_STRIDE;
    rxq->hw_ptr_mask = 0xffff;
    rxq->hw_head_ptr = rxq->hw_addr+MQNIC_QUEUE_HEAD_PTR_REG;
    rxq->hw_tail_ptr = rxq->hw_addr+MQNIC_QUEUE_TAIL_PTR_REG;

    rxq->head_ptr = 0;
    rxq->tail_ptr = 0;
    rxq->clean_tail_ptr = 0;

	rxq->rx_ring_phys_addr = rz->iova;
	rxq->rx_ring = (struct mqnic_desc *) rz->addr;

	/* Allocate software ring. */
	rxq->sw_ring = rte_zmalloc("rxq->sw_ring",
				   sizeof(struct mqnic_rx_entry) * rxq->nb_rx_desc,
				   RTE_CACHE_LINE_SIZE);
	if (rxq->sw_ring == NULL) {
		PMD_INIT_LOG(ERR, "failed to alloc sw_ring");
		mqnic_rx_queue_release(rxq);
		return -ENOMEM;
	}
	PMD_INIT_LOG(DEBUG, "rx sw_ring=%p hw_ring=%p dma_addr=0x%"PRIx64,
		     rxq->sw_ring, rxq->rx_ring, rxq->rx_ring_phys_addr);

	dev->data->rx_queues[queue_idx] = rxq;
	mqnic_reset_rx_queue(rxq);

	return 0;
}

void
mqnic_dev_clear_queues(struct rte_eth_dev *dev)
{
	uint16_t i;
	struct mqnic_tx_queue *txq;
	struct mqnic_rx_queue *rxq;

	for (i = 0; i < dev->data->nb_tx_queues; i++) {
		txq = dev->data->tx_queues[i];
		if (txq != NULL) {
			mqnic_tx_queue_release_mbufs(txq);
			mqnic_reset_tx_queue(txq, dev);
		}
	}

	for (i = 0; i < dev->data->nb_rx_queues; i++) {
		rxq = dev->data->rx_queues[i];
		if (rxq != NULL) {
			mqnic_rx_queue_release_mbufs(rxq);
			mqnic_reset_rx_queue(rxq);
		}
	}
}

void
mqnic_dev_free_queues(struct rte_eth_dev *dev)
{
	uint16_t i;

	for (i = 0; i < dev->data->nb_rx_queues; i++) {
		eth_mqnic_rx_queue_release(dev->data->rx_queues[i]);
		dev->data->rx_queues[i] = NULL;
		rte_eth_dma_zone_free(dev, "rx_ring", i);
	}
	dev->data->nb_rx_queues = 0;

	for (i = 0; i < dev->data->nb_tx_queues; i++) {
		eth_mqnic_tx_queue_release(dev->data->tx_queues[i]);
		dev->data->tx_queues[i] = NULL;
		rte_eth_dma_zone_free(dev, "tx_ring", i);
	}
	dev->data->nb_tx_queues = 0;
}

void
mqnic_dev_deactive_queues(struct rte_eth_dev *dev)
{
	uint16_t i;
	struct mqnic_priv *priv =
		MQNIC_DEV_PRIVATE_TO_PRIV(dev->data->dev_private);

	for (i = 0; i < dev->data->nb_rx_queues; i++) {
		mqnic_deactivate_rx_queue(dev->data->rx_queues[i]);
	}

	for (i = 0; i < dev->data->nb_tx_queues; i++) {
		mqnic_deactivate_tx_queue(dev->data->tx_queues[i]);
	}
	MQNIC_WRITE_FLUSH(priv);
}

/*********************************************************************
 *
 *  Enable receive unit.
 *
 **********************************************************************/

static int
mqnic_alloc_rx_queue_mbufs(struct mqnic_rx_queue *rxq)
{
	struct mqnic_rx_entry *rxe = rxq->sw_ring;
	uint64_t dma_addr;
	unsigned i;

	/* Initialize software ring entries. */
	for (i = 0; i < rxq->nb_rx_desc; i++) {
		volatile struct mqnic_desc *rxd;
		struct rte_mbuf *mbuf = rte_mbuf_raw_alloc(rxq->mb_pool);
		if (mbuf == NULL) {
			PMD_INIT_LOG(ERR, "RX mbuf alloc failed "
				     "queue_id=%hu", rxq->queue_id);
			return -ENOMEM;
		}

		dma_addr = rte_cpu_to_le_64(rte_mbuf_data_iova_default(mbuf));
		rxd = &rxq->rx_ring[i];
		rxd->len = mbuf->buf_len; //right????????
		rxd->addr = dma_addr;
		rxe[i].mbuf = mbuf;

		rxq->head_ptr++;

		if((rxq->head_ptr == 1) || (rxq->head_ptr == rxq->nb_rx_desc)){
			PMD_INIT_LOG(DEBUG, "rxd->len = mbuf->buf_len = %d, dma_addr=0x%lx, rxq->head_ptr=%d", 
				mbuf->buf_len, dma_addr, rxq->head_ptr);
		}
	}

	return 0;
}

int
eth_mqnic_rx_init(struct rte_eth_dev *dev)
{
	struct mqnic_rx_queue *rxq;
	uint16_t i;
	int ret;
	struct mqnic_hw *hw = MQNIC_DEV_PRIVATE_TO_HW(dev->data->dev_private);
	
	PMD_INIT_LOG(DEBUG, "eth_mqnic_rx_init");

	/* Configure and enable each RX queue. */
	for (i = 0; i < dev->data->nb_rx_queues; i++) {

		rxq = dev->data->rx_queues[i];
		if (rxq == NULL) {
			PMD_INIT_LOG(ERR, "invalid rx queue buffer, i = %d.", i);
			return -1;
		}

		rxq->flags = 0;
		rxq->hw = hw;

		/* Allocate buffers for descriptor rings and set up queue */
		ret = mqnic_alloc_rx_queue_mbufs(rxq);
		if (ret)
			return ret;

		mqnic_activate_rxq(rxq, i);
		MQNIC_WRITE_FLUSH(hw);
	}

	if (dev->data->dev_conf.rxmode.offloads & DEV_RX_OFFLOAD_SCATTER) {
		if (!dev->data->scattered_rx)
			PMD_INIT_LOG(DEBUG, "forcing scatter mode");
		dev->rx_pkt_burst = eth_mqnic_recv_scattered_pkts;
		dev->data->scattered_rx = 1;
	}

	return 0;
}

/*********************************************************************
 *
 *  Enable transmit unit.
 *
 **********************************************************************/
void
eth_mqnic_tx_init(struct rte_eth_dev *dev)
{
	struct mqnic_tx_queue *txq;
	uint16_t i;
	struct mqnic_priv *priv =
		MQNIC_DEV_PRIVATE_TO_PRIV(dev->data->dev_private);
	
	PMD_INIT_LOG(DEBUG, "eth_mqnic_tx_init");

	/* Setup the Base and Length of the Tx Descriptor Rings. */
	for (i = 0; i < dev->data->nb_tx_queues; i++) {
		txq = dev->data->tx_queues[i];
		if (txq == NULL) {
			PMD_INIT_LOG(ERR, "invalid tx queue buffer, i = %d.", i);
			return;
		}
		txq->cpl_index = i;
		txq->priv = priv;

		// deactivate queue
		MQNIC_DIRECT_WRITE_REG(txq->hw_addr, MQNIC_QUEUE_ACTIVE_LOG_SIZE_REG, 0);
    	// set base address
		MQNIC_DIRECT_WRITE_REG(txq->hw_addr, MQNIC_QUEUE_BASE_ADDR_REG+0, txq->tx_ring_phys_addr);
		MQNIC_DIRECT_WRITE_REG(txq->hw_addr, MQNIC_QUEUE_BASE_ADDR_REG+4, txq->tx_ring_phys_addr >> 32);
    	// set completion queue index
		MQNIC_DIRECT_WRITE_REG(txq->hw_addr, MQNIC_QUEUE_CPL_QUEUE_INDEX_REG, txq->cpl_index);
    	// set pointers
		MQNIC_DIRECT_WRITE_REG(txq->hw_addr, MQNIC_QUEUE_HEAD_PTR_REG, txq->head_ptr & txq->hw_ptr_mask);
		MQNIC_DIRECT_WRITE_REG(txq->hw_addr, MQNIC_QUEUE_TAIL_PTR_REG, txq->tail_ptr & txq->hw_ptr_mask);
    	// set size and activate queue
		MQNIC_DIRECT_WRITE_REG(txq->hw_addr, MQNIC_QUEUE_ACTIVE_LOG_SIZE_REG, ilog2(txq->size) | (txq->log_desc_block_size << 8) | MQNIC_QUEUE_ACTIVE_MASK);
	}
}

void
mqnic_rxq_info_get(struct rte_eth_dev *dev, uint16_t queue_id,
	struct rte_eth_rxq_info *qinfo)
{
	struct mqnic_rx_queue *rxq;

	rxq = dev->data->rx_queues[queue_id];

	qinfo->mp = rxq->mb_pool;
	qinfo->scattered_rx = dev->data->scattered_rx;
	qinfo->nb_desc = rxq->nb_rx_desc;

	qinfo->conf.rx_free_thresh = rxq->rx_free_thresh;
	qinfo->conf.rx_drop_en = rxq->drop_en;
	qinfo->conf.offloads = rxq->offloads;
}

void
mqnic_txq_info_get(struct rte_eth_dev *dev, uint16_t queue_id,
	struct rte_eth_txq_info *qinfo)
{
	struct mqnic_tx_queue *txq;

	txq = dev->data->tx_queues[queue_id];

	qinfo->nb_desc = txq->nb_tx_desc;

	qinfo->conf.tx_thresh.pthresh = txq->pthresh;
	qinfo->conf.tx_thresh.hthresh = txq->hthresh;
	qinfo->conf.tx_thresh.wthresh = txq->wthresh;
	qinfo->conf.offloads = txq->offloads;
}

