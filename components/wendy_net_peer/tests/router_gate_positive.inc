/* Included only by the focused host route-crypto fixture. Execute production
 * gossip completion and workspace admission, with ordinary signed route data. */
static uint64_t gate_request;
static unsigned gate_wants;
static int gate_emit(void *context,const struct wg_message *message)
{
    (void)context;
    if(message->op==WG_WANT){gate_request=message->request;gate_wants++;}
    return 0;
}
static void gate_owned_route_test(struct endpoint *peer,const uint8_t source[16],
    const uint8_t destination[16],uint64_t expected_link)
{
    struct wnrs *session=peer->session;struct wnrs_node *node=session->node;
    uint8_t uuid[16],signature[80];char body[768],principal[106],wire[1500];
    assert(!wn_uuid_parse(ids[peer->index],uuid));
    struct wn_origin origin={.router_id=peer->remote.config.router,.seqno=peer->remote.seqno};
    int64_t wall=node_unix(node);
    int n=wn_manifest_app_write(uuid,&origin,2,wall,wall+60000,5054,43022,body,sizeof body);
    assert(n>0 && wn_principal(tenant,ids[peer->index],principal)>0);
    size_t signature_size=0;
    assert(!wendy_pki_mesh_sign(NULL,principal,body,(size_t)n,signature,&signature_size));
    n=wn_manifest_wire_write(principal,body,(size_t)n,signature,signature_size,wire,sizeof wire);
    assert(n>0 && n<=WG_CHUNK && !node->pool.pending_count && node->pool.config.downloads==1);
    struct wg_id id={.type=1};assert(!wn_gossip_identify(NULL,1,wire,(size_t)n,id.hash));
    struct wg_message message={.id=id,.op=WG_HAVE};
    assert(!wg_receive(&session->gossip,&message,milliseconds(),gate_emit,complete,session));
    assert(gate_request && gate_wants==1);
    char tls_owner;
    assert(wendy_pki_handshake_claim(&tls_owner));
    message=(struct wg_message){.id=id,.op=WG_DATA,.request=gate_request,
        .total=(uint32_t)n,.data=(const uint8_t *)wire,.size=(size_t)n};
    assert(!wg_receive(&session->gossip,&message,milliseconds(),gate_emit,complete,session));
    assert(node->pool.pending_count==1 && node->pool.pending);
    assert(!session->record_verification && !session->verification_blocked && !wnrs_receive_paused(session));
    /* The retained complete body already occupies this node's one download
     * slot. Another ordinary hint cannot start another payload allocation. */
    struct wg_id waiting=id;waiting.hash[0]^=1;
    message=(struct wg_message){.id=waiting,.op=WG_HAVE};
    assert(!wg_receive(&session->gossip,&message,milliseconds(),gate_emit,complete,session));
    assert(gate_wants==1 && node->pool.pending_count==2);
    /* This is the following packet that the outer carrier reader must remain
     * able to deliver while VIP TLS is waiting for network I/O. */
    uint8_t packet[40]={0x60};packet[6]=59;packet[7]=8;
    memcpy(packet+8,source,16);memcpy(packet+24,destination,16);
    uint64_t outgoing=0;
    assert(wnrs_packet_route(session,packet,sizeof packet,true,&outgoing)==1);
    assert(outgoing==expected_link && packet[7]==7);
    wendy_pki_handshake_release(&tls_owner);
    assert(!wg_resume(&session->gossip,complete,session));
    assert(session->record_verification && session->verification_blocked && wnrs_receive_paused(session));
    assert(wendy_pki_work_poll());
#if defined(WENDY_NET_MEMORY_HOST_BUDGET_TEST)
    /* Ordinary overlap consumes the remaining ledger budget. There is less
     * room than the parser needs until the completed CPU copy is reaped. */
    wendy_net_memory_snapshot_t memory;wendy_net_runtime_memory_snapshot(&memory);
    size_t headroom=sizeof(struct wn_doc)-64;
    assert(memory.limit_bytes>memory.current_bytes+headroom);
    wendy_net_memory_reservation_t pressure={0};
    assert(wendy_net_memory_reserve(wendy_net_runtime_memory_ledger(),&pressure,
        memory.limit_bytes-memory.current_bytes-headroom,WENDY_NET_MEMORY_INTERNAL));
#endif
    int resumed=wg_resume(&session->gossip,complete,session);assert(resumed>=0);
    assert(!session->record_verification && !session->verification_blocked && !wnrs_receive_paused(session));
    assert(!wendy_pki_handshake_busy());
#if defined(WENDY_NET_MEMORY_HOST_BUDGET_TEST)
    wendy_net_memory_release(&pressure);
#endif
    /* Smaller completed-job headers can leave less parser/hash headroom.
     * Completion still releases its loan first, then resumes without reverify. */
    if(!resumed)assert(wg_resume(&session->gossip,complete,session)==1);
    assert(!wendy_pki_work_poll());
    struct wnd_entry *entry=node->core.directory.entries;
    while(entry && memcmp(entry->device,uuid,16))entry=entry->next;
    assert(entry && entry->revision==2 && node->pool.pending_count==1);
    message=(struct wg_message){.id=waiting,.op=WG_GONE};
    assert(!wg_receive(&session->gossip,&message,milliseconds(),gate_emit,complete,session));
    assert(!node->pool.pending_count);
}
