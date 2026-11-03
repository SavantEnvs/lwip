/* libFuzzer entry for the three upstream test/fuzz programs (fuzz.c / fuzz2.c / fuzz3.c).
 * FUZZ_VARIANT selects which one: 1 = single frame, 2 = multi-packet, 3 = multi-packet + time + apps.
 * Stack setup mirrors lwip_fuzztest() in test/fuzz/fuzz_common.c; here it runs once and every input is
 * replayed into the same stack, with all TCP pcbs aborted afterwards so inputs stay independent. */
#include "../test/fuzz/fuzz_common.c"

#include "lwip/tcp.h"
#include "lwip/priv/tcp_priv.h"

#if FUZZ_VARIANT == 1
#define FUZZ_TYPE LWIP_FUZZ_SINGLE
#define FUZZ_APPS LWIP_FUZZ_DEFAULT
#elif FUZZ_VARIANT == 2
#define FUZZ_TYPE LWIP_FUZZ_MULTIPACKET
#define FUZZ_APPS LWIP_FUZZ_DEFAULT
#elif FUZZ_VARIANT == 3
#define FUZZ_TYPE LWIP_FUZZ_MULTIPACKET_TIME
#define FUZZ_APPS (LWIP_FUZZ_STATICARP|LWIP_FUZZ_TCP_SERVER|LWIP_FUZZ_TCP_CLIENT|LWIP_FUZZ_UDP_SERVER|LWIP_FUZZ_UDP_CLIENT)
#else
#error "FUZZ_VARIANT must be 1, 2 or 3"
#endif

/* Virtual clock: time only moves by the delays carried in the input, so a run is reproducible. Each
 * advance is capped to ~74 hours where the clock is read, whatever consumed the delay words: one jump of
 * 2^31 ms or more makes lwIP's modular timer arithmetic misjudge pending timers and later trips "invalid
 * sleeptime", a harness artifact rather than an application bug. */
#define MAX_CLOCK_STEP 0x0fffffffU
u32_t sys_now(void)
{
  static u32_t last_offset;
  static u32_t virtual_now;
  u32_t step = sys_now_offset - last_offset;
  last_offset = sys_now_offset;
  virtual_now += LWIP_MIN(step, MAX_CLOCK_STEP);
  return virtual_now;
}

static struct netif net_test;
static ip_addr_t remote_addr;
static int stack_ready;

static void open_client_connection(void)
{
  if (FUZZ_APPS & LWIP_FUZZ_TCP_CLIENT) {
    err_t err;
    tcp_client_pcb = altcp_tcp_new_ip_type(IPADDR_TYPE_ANY);
    LWIP_ASSERT("Error: altcp_new() failed", tcp_client_pcb != NULL);
    tcp_remote_port = 80;
    err = altcp_connect(tcp_client_pcb, &remote_addr, tcp_remote_port, tcp_client_connected);
    LWIP_ASSERT("Error: altcp_connect() failed", err == ERR_OK);
    altcp_recv(tcp_client_pcb, tcp_client_recv);
    altcp_err(tcp_client_pcb, tcp_client_err);
    altcp_poll(tcp_client_pcb, tcp_client_poll, 10);
    altcp_sent(tcp_client_pcb, tcp_client_sent);
  }
}

static void stack_setup(void)
{
  ip4_addr_t addr, netmask, gw;
  struct eth_addr remote_mac = ETH_ADDR(0x28, 0x00, 0x00, 0x22, 0x2b, 0x38);

  lwip_init();

  IP4_ADDR(&addr, 172, 30, 115, 84);
  IP4_ADDR(&netmask, 255, 255, 255, 0);
  IP4_ADDR(&gw, 172, 30, 115, 1);
  netif_add(&net_test, &addr, &netmask, &gw, &net_test, testif_init, ethernet_input);
  netif_set_up(&net_test);
  netif_set_link_up(&net_test);

  IP_ADDR4(&remote_addr, 172, 30, 115, 37);
  if (FUZZ_APPS & LWIP_FUZZ_STATICARP) {
    etharp_add_static_entry(&(remote_addr.u_addr.ip4), &remote_mac);
  }

#if LWIP_IPV6
  nd6_tmr();
#endif
  dns_setserver(0, &net_test.gw);

  if (FUZZ_APPS & LWIP_FUZZ_DEFAULT) {
    httpd_init();
    lwiperf_start_tcp_server_default(NULL, NULL);
    mdns_resp_init();
    mdns_resp_add_netif(&net_test, "hostname");
    snmp_init();
  }
  if (FUZZ_APPS & LWIP_FUZZ_TCP_SERVER) {
    err_t err;
    tcp_server_pcb = altcp_tcp_new_ip_type(IPADDR_TYPE_ANY);
    LWIP_ASSERT("Error: altcp_new() failed", tcp_server_pcb != NULL);
    altcp_setprio(tcp_server_pcb, TCP_PRIO_MIN);
    tcp_local_port = 80;
    err = altcp_bind(tcp_server_pcb, IP_ANY_TYPE, tcp_local_port);
    LWIP_ASSERT("Error: altcp_bind() failed", err == ERR_OK);
    tcp_server_pcb = altcp_listen(tcp_server_pcb);
    LWIP_ASSERT("Error: altcp_listen() failed", tcp_server_pcb != NULL);
    altcp_accept(tcp_server_pcb, tcp_server_accept);
  }
  if (FUZZ_APPS & LWIP_FUZZ_UDP_CLIENT) {
    udp_client_pcb = udp_new_ip_type(IPADDR_TYPE_ANY);
    udp_recv(udp_client_pcb, udp_client_recv, NULL);
    udp_remote_port = 161;
    udp_connect(udp_client_pcb, &remote_addr, udp_remote_port);
  }
  if (FUZZ_APPS & LWIP_FUZZ_UDP_SERVER) {
    udp_server_pcb = udp_new_ip_type(IPADDR_TYPE_ANY);
    udp_local_port = 161;
    udp_bind(udp_server_pcb, IP_ANY_TYPE, udp_local_port);
    udp_recv(udp_server_pcb, udp_server_recv, NULL);
  }
}

static void abort_connections(void)
{
  struct tcp_pcb *pcb, *next;
  for (pcb = tcp_active_pcbs; pcb != NULL; pcb = next) {
    next = pcb->next;
    tcp_abort(pcb);
  }
  for (pcb = tcp_tw_pcbs; pcb != NULL; pcb = next) {
    next = pcb->next;
    tcp_abort(pcb);
  }
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
  if (size == 0) {
    return -1;
  }
  if (size > sizeof(pktbuf)) {
    size = sizeof(pktbuf);
  }
  if (!stack_ready) {
    stack_setup();
    stack_ready = 1;
  }
  remfuzz_ptr = data;
  remfuzz_len = 0;
  open_client_connection();
  input_pkts(FUZZ_TYPE, &net_test, data, size);
  abort_connections();
  return 0;
}
