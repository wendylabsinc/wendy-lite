# Native agent and guest VIP streams

The actor owns application TLS contexts and routes native WendyCom through the
same established encrypted link as SensorLink and ConsoleAttach. It does not
add another WendyCom TLS wrapper. Guest TCP/UDP services retain their ordinary
application authorization, advertised by the complete signed manifest.

On constrained devices, incoming native management may cancel an unestablished
outgoing guest setup holding the sole handshake workspace. It waits for the
loan to return; established guest flows are not sacrificed. Native sockets
reach the actor before baseline physical TLS memory admission; the existing
server retains at most one deferred physical descriptor with a deadline.

Persisted settings, radio selection, public SDK replay, supported board defaults
and final legacy retirement remain in the following cutover layer. No additional
operator-origin protocol or independently signed service records are enabled.

Normal stream completion drains accepted plaintext and encrypted output; explicit
OFF waits for the crypto loan and WendyCom close acknowledgement before freeing
managed state. TLS disposal and certificate-source handle closure are worker
effects. Existing app-owned socket state remains separate from mesh ownership.

The cutover layer must acknowledge a ConfigureNet command over the current
transport before stopping that transport. WendyCom accepting a response into its
plaintext queue is not the same as the actor draining its encrypted BIO to the
socket. The management delegate must coordinate both completion boundaries;
applying OFF inline before its own reply has drained will discard the reply.
