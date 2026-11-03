package whatsmeow

import (
	"fmt"
	"strings"
	"sync"

	"google.golang.org/protobuf/encoding/protowire"

	waBinary "go.mau.fi/whatsmeow/binary"
	"go.mau.fi/whatsmeow/types"
)

var loggedUnknownSignalFields sync.Map

func unknownProtoFields(b []byte, known func(protowire.Number) bool) (unknown []string, inner []byte) {
	for len(b) > 0 {
		num, typ, n := protowire.ConsumeTag(b)
		if n < 0 {
			return append(unknown, "bad_tag"), inner
		}
		b = b[n:]
		m := protowire.ConsumeFieldValue(num, typ, b)
		if m < 0 {
			return append(unknown, fmt.Sprintf("%d:bad", num)), inner
		}
		if num == 4 && typ == protowire.BytesType {
			inner, _ = protowire.ConsumeBytes(b)
		}
		if !known(num) {
			switch typ {
			case protowire.VarintType:
				v, _ := protowire.ConsumeVarint(b)
				unknown = append(unknown, fmt.Sprintf("%d=%d", num, v))
			case protowire.BytesType:
				v, _ := protowire.ConsumeBytes(b)
				unknown = append(unknown, fmt.Sprintf("%d=bytes(%d):%x", num, len(v), v[:min(len(v), 16)]))
			default:
				unknown = append(unknown, fmt.Sprintf("%d=wiretype%d", num, typ))
			}
		}
		b = b[m:]
	}
	return
}

func (cli *Client) logUnknownSignalFields(from types.JID, isPreKey bool, content []byte, child *waBinary.Node) {
	if len(content) < 10 {
		return
	}
	var outerUnknown []string
	signalMsg := content
	if isPreKey {
		outerUnknown, signalMsg = unknownProtoFields(content[1:], func(n protowire.Number) bool { return n >= 1 && n <= 6 })
		if len(signalMsg) < 10 {
			return
		}
	}
	innerUnknown, _ := unknownProtoFields(signalMsg[1:len(signalMsg)-8], func(n protowire.Number) bool { return n >= 1 && n <= 4 })
	key := fmt.Sprintf("%s|%v|%s|%s", from, isPreKey, strings.Join(outerUnknown, ","), strings.Join(innerUnknown, ","))
	if _, loaded := loggedUnknownSignalFields.LoadOrStore(key, struct{}{}); loaded {
		return
	}
	cli.Log.Warnf("Signal message field census from %s: prekey=%v version=0x%02x attrs=%v outer_unknown=[%s] inner_unknown=[%s]",
		from, isPreKey, content[0], child.Attrs, strings.Join(outerUnknown, ","), strings.Join(innerUnknown, ","))
}
