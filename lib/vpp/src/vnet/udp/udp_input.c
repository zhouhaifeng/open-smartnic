/*
 * Copyright (c) 2016-2019 Cisco and/or its affiliates.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <vlibmemory/api.h>
#include <vlib/vlib.h>

#include <vppinfra/hash.h>
#include <vppinfra/error.h>
#include <vppinfra/elog.h>

#include <vnet/vnet.h>
#include <vnet/pg/pg.h>
#include <vnet/ip/ip.h>
#include <vnet/udp/udp.h>
#include <vnet/udp/udp_packet.h>
#include <vnet/session/session.h>

static char *udp_error_strings[] = {
#define udp_error(n,s) s,
#include "udp_error.def"
#undef udp_error
};

typedef struct
{
  u32 connection;
  u32 disposition;
  u32 thread_index;
} udp_input_trace_t;

/* packet trace format function */
static u8 *
format_udp_input_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  udp_input_trace_t *t = va_arg (*args, udp_input_trace_t *);

  s = format (s, "UDP_INPUT: connection %d, disposition %d, thread %d",
	      t->connection, t->disposition, t->thread_index);
  return s;
}

#define foreach_udp_input_next			\
  _ (DROP, "error-drop")

typedef enum
{
#define _(s, n) UDP_INPUT_NEXT_##s,
  foreach_udp_input_next
#undef _
    UDP_INPUT_N_NEXT,
} udp_input_next_t;

always_inline void
udp_input_inc_counter (vlib_main_t * vm, u8 is_ip4, u8 evt, u8 val)
{
  if (PREDICT_TRUE (!val))
    return;

  if (is_ip4)
    vlib_node_increment_counter (vm, udp4_input_node.index, evt, val);
  else
    vlib_node_increment_counter (vm, udp6_input_node.index, evt, val);
}

always_inline uword
udp46_input_inline (vlib_main_t * vm, vlib_node_runtime_t * node,
		    vlib_frame_t * frame, u8 is_ip4)
{
  u32 n_left_from, *from, *to_next;
  u32 next_index, errors;
  u32 my_thread_index = vm->thread_index;

  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;
  next_index = node->cached_next_index;

  while (n_left_from > 0)
    {
      u32 n_left_to_next;

      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

      while (n_left_from > 0 && n_left_to_next > 0)
	{
	  u32 bi0, fib_index0;
	  vlib_buffer_t *b0;
	  u32 next0 = UDP_INPUT_NEXT_DROP;
	  u32 error0 = UDP_ERROR_ENQUEUED;
	  udp_header_t *udp0;
	  ip4_header_t *ip40;
	  ip6_header_t *ip60;
	  u8 *data0;
	  session_t *s0;
	  udp_connection_t *uc0, *child0, *new_uc0;
	  transport_connection_t *tc0;
	  int wrote0;
	  void *rmt_addr, *lcl_addr;
	  session_dgram_hdr_t hdr0;

	  /* speculatively enqueue b0 to the current next frame */
	  bi0 = from[0];
	  to_next[0] = bi0;
	  from += 1;
	  to_next += 1;
	  n_left_from -= 1;
	  n_left_to_next -= 1;

	  b0 = vlib_get_buffer (vm, bi0);

	  /* udp_local hands us a pointer to the udp data */
	  data0 = vlib_buffer_get_current (b0);
	  udp0 = (udp_header_t *) (data0 - sizeof (*udp0));
	  fib_index0 = vnet_buffer (b0)->ip.fib_index;

	  if (is_ip4)
	    {
	      /* TODO: must fix once udp_local does ip options correctly */
	      ip40 = (ip4_header_t *) (((u8 *) udp0) - sizeof (*ip40));
	      s0 = session_lookup_safe4 (fib_index0, &ip40->dst_address,
					 &ip40->src_address, udp0->dst_port,
					 udp0->src_port, TRANSPORT_PROTO_UDP);
	      lcl_addr = &ip40->dst_address;
	      rmt_addr = &ip40->src_address;

	    }
	  else
	    {
	      ip60 = (ip6_header_t *) (((u8 *) udp0) - sizeof (*ip60));
	      s0 = session_lookup_safe6 (fib_index0, &ip60->dst_address,
					 &ip60->src_address, udp0->dst_port,
					 udp0->src_port, TRANSPORT_PROTO_UDP);
	      lcl_addr = &ip60->dst_address;
	      rmt_addr = &ip60->src_address;
	    }

	  if (PREDICT_FALSE (!s0))
	    {
	      error0 = UDP_ERROR_NO_LISTENER;
	      goto trace0;
	    }

	  if (s0->session_state == SESSION_STATE_OPENED)
	    {
	      /* TODO optimization: move cl session to right thread
	       * However, since such a move would affect the session handle,
	       * which we pass 'raw' to the app, we'd also have notify the
	       * app of the change or change the way we pass handles to apps.
	       */
	      tc0 = session_get_transport (s0);
	      uc0 = udp_get_connection_from_transport (tc0);
	      if (uc0->flags & UDP_CONN_F_CONNECTED)
		{
		  if (s0->thread_index != vlib_get_thread_index ())
		    {
		      /*
		       * Clone the transport. It will be cleaned up with the
		       * session once we notify the session layer.
		       */
		      new_uc0 =
			udp_connection_clone_safe (s0->connection_index,
						   s0->thread_index);
		      ASSERT (s0->session_index == new_uc0->c_s_index);

		      /*
		       * Drop the 'lock' on pool resize
		       */
		      session_pool_remove_peeker (s0->thread_index);
		      session_dgram_connect_notify (&new_uc0->connection,
						    s0->thread_index, &s0);
		      tc0 = &new_uc0->connection;
		    }
		  else
		    s0->session_state = SESSION_STATE_READY;
		}
	    }
	  else if (s0->session_state == SESSION_STATE_READY)
	    {
	      tc0 = session_get_transport (s0);
	      uc0 = udp_get_connection_from_transport (tc0);
	    }
	  else if (s0->session_state == SESSION_STATE_LISTENING)
	    {
	      tc0 = listen_session_get_transport (s0);
	      uc0 = udp_get_connection_from_transport (tc0);
	      if (uc0->flags & UDP_CONN_F_CONNECTED)
		{
		  child0 = udp_connection_alloc (my_thread_index);
		  if (is_ip4)
		    {
		      ip_set (&child0->c_lcl_ip, &ip40->dst_address, 1);
		      ip_set (&child0->c_rmt_ip, &ip40->src_address, 1);
		    }
		  else
		    {
		      ip_set (&child0->c_lcl_ip, &ip60->dst_address, 0);
		      ip_set (&child0->c_rmt_ip, &ip60->src_address, 0);
		    }
		  child0->c_lcl_port = udp0->dst_port;
		  child0->c_rmt_port = udp0->src_port;
		  child0->c_is_ip4 = is_ip4;
		  child0->c_fib_index = tc0->fib_index;
		  child0->flags |= UDP_CONN_F_CONNECTED;

		  if (session_stream_accept (&child0->connection,
					     tc0->s_index, tc0->thread_index,
					     1))
		    {
		      error0 = UDP_ERROR_CREATE_SESSION;
		      goto trace0;
		    }
		  s0 =
		    session_get (child0->c_s_index, child0->c_thread_index);
		  s0->session_state = SESSION_STATE_READY;
		  tc0 = &child0->connection;
		  uc0 = udp_get_connection_from_transport (tc0);
		  error0 = UDP_ERROR_LISTENER;
		}
	    }
	  else
	    {
	      error0 = UDP_ERROR_NOT_READY;
	      goto trace0;
	    }


	  if (svm_fifo_max_enqueue_prod (s0->rx_fifo)
	      < b0->current_length + sizeof (session_dgram_hdr_t))
	    {
	      error0 = UDP_ERROR_FIFO_FULL;
	      goto trace0;
	    }
	  hdr0.data_length = b0->current_length;
	  hdr0.data_offset = 0;
	  ip_set (&hdr0.lcl_ip, lcl_addr, is_ip4);
	  ip_set (&hdr0.rmt_ip, rmt_addr, is_ip4);
	  hdr0.lcl_port = udp0->dst_port;
	  hdr0.rmt_port = udp0->src_port;
	  hdr0.is_ip4 = is_ip4;

	  clib_spinlock_lock (&uc0->rx_lock);
	  wrote0 = session_enqueue_dgram_connection (s0, &hdr0, b0,
						     TRANSPORT_PROTO_UDP,
						     1 /* queue evt */ );
	  clib_spinlock_unlock (&uc0->rx_lock);
	  ASSERT (wrote0 > 0);

	  if (s0->session_state != SESSION_STATE_LISTENING)
	    session_pool_remove_peeker (s0->thread_index);

	trace0:

	  b0->error = node->errors[error0];

	  if (PREDICT_FALSE ((node->flags & VLIB_NODE_FLAG_TRACE)
			     && (b0->flags & VLIB_BUFFER_IS_TRACED)))
	    {
	      udp_input_trace_t *t = vlib_add_trace (vm, node, b0,
						     sizeof (*t));

	      t->connection = s0 ? s0->connection_index : ~0;
	      t->disposition = error0;
	      t->thread_index = my_thread_index;
	    }

	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index,
					   to_next, n_left_to_next,
					   bi0, next0);
	}

      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  errors = session_main_flush_all_enqueue_events (TRANSPORT_PROTO_UDP);
  udp_input_inc_counter (vm, is_ip4, UDP_ERROR_EVENT_FIFO_FULL, errors);
  return frame->n_vectors;
}


static uword
udp4_input (vlib_main_t * vm, vlib_node_runtime_t * node,
	    vlib_frame_t * frame)
{
  return udp46_input_inline (vm, node, frame, 1);
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (udp4_input_node) =
{
  .function = udp4_input,
  .name = "udp4-input",
  .vector_size = sizeof (u32),
  .format_trace = format_udp_input_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = ARRAY_LEN (udp_error_strings),
  .error_strings = udp_error_strings,
  .n_next_nodes = UDP_INPUT_N_NEXT,
  .next_nodes = {
#define _(s, n) [UDP_INPUT_NEXT_##s] = n,
      foreach_udp_input_next
#undef _
  },
};
/* *INDENT-ON* */

static uword
udp6_input (vlib_main_t * vm, vlib_node_runtime_t * node,
	    vlib_frame_t * frame)
{
  return udp46_input_inline (vm, node, frame, 0);
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (udp6_input_node) =
{
  .function = udp6_input,
  .name = "udp6-input",
  .vector_size = sizeof (u32),
  .format_trace = format_udp_input_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = ARRAY_LEN (udp_error_strings),
  .error_strings = udp_error_strings,
  .n_next_nodes = UDP_INPUT_N_NEXT,
  .next_nodes = {
#define _(s, n) [UDP_INPUT_NEXT_##s] = n,
      foreach_udp_input_next
#undef _
  },
};
/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
