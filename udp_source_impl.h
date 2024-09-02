/* -*- c++ -*- */
/*
 * Copyright 2017,2019,2020 ghostop14.
 *
 * This is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3, or (at your option)
 * any later version.
 *
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this software; see the file COPYING.  If not, write to
 * the Free Software Foundation, Inc., 51 Franklin Street,
 * Boston, MA 02110-1301, USA.
 */

#ifndef INCLUDED_GRNET_udp_source_impl_H
#define INCLUDED_GRNET_udp_source_impl_H

#include <boost/asio.hpp>
#include <boost/asio/ip/udp.hpp>
#include <boost/circular_buffer.hpp>
#include <gnuradio/grnet/udp_source.h>

#include <queue>
#include <vector>

#include "packet_headers.h"

namespace gr {
namespace grnet {

class GRNET_API udp_source_impl : public udp_source {		
     /*
     public:
     	using gr::sync_decimator::message_port_register_in;
     	
    	using gr::sync_decimator::set_msg_handler;

		using gr::sync_decimator::basic_block;
    	
		//gr::sync_decimator d_sync_decimator;
	*/
	
	public:
		using sptr = std::shared_ptr<udp_source_impl>;
		//typedef std::shared_ptr<multDivSelect_impl> sptr;

		/*!
		 * \brief Return a shared_ptr to a new instance of customModule::multDivSelect.
		 *
		 * To avoid accidental use of raw pointers, customModule::multDivSelect's
		 * constructor is in a private implementation
		 * class. customModule::multDivSelect::make is the public interface for
		 * creating new instances.
		 */
		
		static sptr make(uint16_t spacecraft_id, uint8_t version, int decim, bool randomizer, int sine_samples, int acq_samples);
		
		
		//static udp_source_impl::sptr make(unsigned short, unsigned char, int, bool, int, int);

	
     public:
      //----------------config parameters-----------------
      //message input port
      pmt::pmt_t d_pdu_port;
      //decimation factor
      int decim;
      //ccsds tc use randomizer or not
      bool randomizer;
      //ccsds tc plop-2 cmm-1 sine wave (all zero) sequence length (samples)
      int sine_samples;
      //ccsds tc plop-2 cmm-1 acquisition (0b01010101) sequence length (samples)
      int acq_samples;
      
      //----------------variables-------------------------
      uint16_t spacecraft_id;
      uint8_t version;
      //message input buffer
      std::queue<std::vector<uint8_t> > q;
      //cltu output buffer
      uint8_t buf[512];
      int bufpos;
      int buflen;
      //sine wave sequence counter
      int sine_count;
      //acquisition sequence counter
      int acq_count;
      //uplink state
      enum uplink_state_t {
		plop_sine, 
		plop_acq, 
		plop_idle,
		plop_off
	  } stat;
	  static const int payload_bytes = 220;
	  static const int up_ip_bytes = 224;
	  
	  void on();
	  void off();
	  
	  void buf_reset();
	  void buf_push(uint8_t x);
	  void make_cltus();
	  
	  void pdu_callback(pmt::pmt_t msg);
	  
     public:
      udp_source_impl(uint16_t spacecraft_id, uint8_t version, int decim, bool randomizer, int sine_samples, int acq_samples);
      ~udp_source_impl();

	  bool start();
      // Where all the action really happens
      int work (int noutput_items,
                       gr_vector_const_void_star &input_items,
                       gr_vector_void_star &output_items);
    };
    


/*
class GRNET_API udp_source_impl : public udp_source {
protected:
  size_t d_itemsize;
  size_t d_veclen;
  size_t d_block_size;

  bool d_notifyMissed;
  bool d_sourceZeros;
  int d_partialFrameCounter;

  bool is_ipv6;

  int d_port;
  int d_header_type;
  int d_header_size;
  uint16_t d_payloadsize;
  int d_precompDataSize;
  int d_precompDataOverItemSize;
  long d_udp_recv_buf_size;

  uint64_t d_seq_num;

  boost::system::error_code ec;

  boost::asio::io_service d_io_service;
  boost::asio::ip::udp::endpoint d_endpoint;
  boost::asio::ip::udp::socket *d_udpsocket;

  boost::asio::streambuf d_read_buffer;

  // A queue is required because we have 2 different timing
  // domains: The network packets and the GR work()/scheduler
  boost::circular_buffer<char> *d_localqueue;
  char *localBuffer;

  uint64_t get_header_seqnum();

public:
  udp_source_impl(size_t itemsize, size_t vecLen, int port, int headerType,
                  int payloadsize, bool notifyMissed,
                  bool sourceZeros, bool ipv6);
  ~udp_source_impl();

  bool stop();

  size_t data_available();
  inline size_t netdata_available();

  // Where all the action really happens
  int work_test(int noutput_items, gr_vector_const_void_star &input_items,
                gr_vector_void_star &output_items);
  int work(int noutput_items, gr_vector_const_void_star &input_items,
           gr_vector_void_star &output_items);
};*/

} // namespace grnet
} // namespace gr

#endif /* INCLUDED_GRNET_udp_source_impl_H */
