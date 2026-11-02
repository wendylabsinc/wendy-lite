package litepb

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"testing"

	"google.golang.org/protobuf/proto"
)

func TestTopologyNanopbNormalTypedOperatorRoundTrip(t *testing.T) {
	hexWire, err := os.ReadFile("../../../components/wendy_com/tests/fixtures/topology_operator_page.hex")
	if err != nil {
		t.Fatal(err)
	}
	wire, err := hex.DecodeString(strings.TrimSpace(string(hexWire)))
	if err != nil {
		t.Fatal(err)
	}
	message := new(WendyComMessage)
	if err := proto.Unmarshal(wire, message); err != nil {
		t.Fatal(err)
	}
	row := message.GetResponse().GetNetTopology().GetRecord()
	if row.GetOwnerRole() != 2 || row.GetOwnerPrincipal() != "spiffe://wendy.sh/tenant/11111111-1111-4111-8111-111111111111/operator/Alice" || len(row.Device) != 0 {
		t.Fatal("operator was recast as an enrolled device", row)
	}
	if len(row.OwnerInstance) != 16 {
		t.Fatal("missing routing installation UUID")
	}
	b := row.OwnerInstance
	instance := fmt.Sprintf("%x-%x-%x-%x-%x", b[:4], b[4:6], b[6:8], b[8:10], b[10:])
	address, ok := netip.AddrFromSlice(row.Address)
	if !ok {
		t.Fatal("missing IPv6 bytes")
	}
	// A public adapter converts bytes before JSON. Never marshal the generated
	// protobuf's []byte owner_instance/address directly into a UI envelope.
	projection := struct {
		Principal string `json:"principal"`
		Instance  string `json:"routingInstance"`
		Address   string `json:"address"`
		RouterID  string `json:"routerId"`
		Revision  string `json:"revision"`
	}{row.OwnerPrincipal, instance, address.String(), strconv.FormatUint(row.RouterId, 10), strconv.FormatUint(row.Revision, 10)}
	publicJSON, err := json.Marshal(projection)
	if err != nil {
		t.Fatal(err)
	}
	expected := `{"principal":"spiffe://wendy.sh/tenant/11111111-1111-4111-8111-111111111111/operator/Alice","routingInstance":"aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa","address":"fd45:b891:5680:cca:1cd7:f65e:b581:101b","routerId":"18446744073709551614","revision":"18446744073709551615"}`
	if string(publicJSON) != expected {
		t.Fatal(string(publicJSON))
	}
	encoded, err := proto.MarshalOptions{Deterministic: true}.Marshal(message)
	if err != nil || !bytes.Equal(encoded, wire) {
		t.Fatal("C nanopb and Go binary protobuf disagree", err)
	}
}
