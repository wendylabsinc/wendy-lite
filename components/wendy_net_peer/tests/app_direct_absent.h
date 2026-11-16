/* This ordinary-service fixture has no retained BLE epoch. */
unsigned wn_app_direct_incoming_capacity(void)
{
    return 3;
}
bool wendy_net_peer_direct_connect_now(const char *peer, uint16_t port, bool datagram, int fd,
                                       int64_t deadline)
{
    return false;
}
int wn_app_direct_control_begin(wendy_pki_connection *c, const struct wendy_pki_mesh_identity *i,
                                const uint8_t instance[16], bool initiator, uint64_t serial,
                                struct wn_direct_peer **p, uint64_t *token)
{
    assert(!"unexpected promotion");
    return -1;
}
void wn_app_direct_control_close(struct wn_direct_peer *p, uint64_t token)
{
    assert(!p);
}
int wn_app_direct_flow_pin(wendy_pki_connection *c, const struct wendy_pki_mesh_identity *i,
                           const uint8_t hello[64], struct wn_direct_peer **p)
{
    assert(!"unexpected promotion");
    return -1;
}
void wn_app_direct_flow_release(struct wn_direct_peer *p)
{
    assert(!p);
}
int wn_app_direct_open(struct wn_direct_peer *p, uint32_t id)
{
    assert(!"unexpected promotion");
    return -1;
}
bool wendy_net_peer_upper_blocked_now(const char *peer)
{
    (void)peer;
    return false;
}
void wendy_net_set_mesh_waker(void (*wake)(void))
{
    (void)wake;
}
int wendy_net_guest_datagram_deliver_retained(int owner, int *association, uint8_t **packet,
                                              size_t size, unsigned maximum,
                                              wendy_net_packet_release_fn release)
{
    assert(!"unexpected retained datagram");
    return -1;
}
