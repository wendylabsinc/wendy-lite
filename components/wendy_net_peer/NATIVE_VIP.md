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

Persisted WendyCom settings select the supported runtime and constrained boot
radio. Guest SDK intent stays in guest memory and replays on enable. The old
special leaf runtime is removed; all carriers use the ordinary native protocol.
No independently signed service record protocol is enabled.

Normal stream completion drains accepted plaintext and encrypted output; explicit
OFF waits for the crypto loan and WendyCom close acknowledgement before freeing
managed state. TLS disposal and certificate-source handle closure are worker
effects. Existing app-owned socket state remains separate from mesh ownership.

Management must send the response to a ConfigureNet command over the current
transport before stopping that transport. WendyCom accepting a response into its
plaintext queue is not the same as the actor draining its encrypted BIO to the
socket. The management delegate must coordinate both completion boundaries;
applying OFF inline before its own reply has drained will discard the reply.

## Applying management changes

ConfigureNet persists only the device's own desired policy, then returns a
bounded receipt token internally. The command dispatcher finishes the complete
response before handing that token to its transport. Direct TLS/UART transports
have already accepted their output. Physical BLE waits for its retained SDU to
leave the stalled/backoff state; native VIP streams wait for their plaintext
pipe and encrypted TLS BIO output. The actor also samples each native BLE
mailbox so a positive stream write cannot hide a still-pending/stalled SDU.
These are local host-queue fences, not controller or remote acknowledgements.
Context retirement completes the handoff if the client has gone away.

The actor then gives the outer IP/carrier driver at least 250 ms and waits for
its bounded output queues to empty. Unrelated continuous traffic can defer this
stage by at most five seconds; a client lost before response completion can
retain the previous policy for at most 45 seconds. These are local send fences,
not proof of remote receipt during a radio failure. No new task, blocking actor
I/O or unbounded response queue is introduced. A second configuration change
returns BUSY while this handoff is pending.

OFF and non-reboot updates use this same fence. A radio-switch restart reports
APPLIED_RESTARTING in the response and waits for actual actor/worker loan and
allocation retirement before rebooting. The baseline server drives enablement
while no mesh actor exists. All peer caches and session state remain in RAM;
only explicit desired settings and the established own identity boot/certificate
policy use persistent storage.
