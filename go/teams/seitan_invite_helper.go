package teams

import (
	"context"
	"fmt"
	"time"

	"github.com/keybase/client/go/libkb"
	"github.com/keybase/client/go/protocol/keybase1"
)

func ParseAndAcceptSeitanToken(ctx context.Context, g *libkb.GlobalContext, tok string) (wasSeitan bool, err error) {
	seitanVersion, err := DeriveSeitanVersionFromToken(tok)
	if err != nil {
		return wasSeitan, err
	}
	mctx := libkb.NewMetaContext(ctx, g)
	switch seitanVersion {
	case SeitanVersion1:
		wasSeitan, err = parseAndAcceptSeitanTokenV1(mctx, tok)
	case SeitanVersion2:
		wasSeitan, err = parseAndAcceptSeitanTokenV2(ctx, g, tok)
	case SeitanVersionInvitelink:
		wasSeitan, err = parseAndAcceptSeitanTokenInvitelink(ctx, g, tok)
	default:
		wasSeitan = false
		err = fmt.Errorf("Unexpected SeitanVersion %d", seitanVersion)
	}
	return wasSeitan, err
}

func parseAndAcceptSeitanTokenV1(mctx libkb.MetaContext, tok string) (wasSeitan bool, err error) {
	seitan, err := ParseIKeyFromString(tok)
	if err != nil {
		mctx.Debug("ParseIKeyFromString error: %s", err)
		mctx.Debug("returning TeamInviteBadToken instead")
		return false, libkb.TeamInviteBadTokenError{}
	}
	unixNow := mctx.G().Clock().Now().Unix()
	acpt, err := generateAcceptanceSeitanV1(mctx, seitan, unixNow)
	if err != nil {
		return true, err
	}
	err = postSeitanV1(mctx, acpt)
	return true, err
}

type acceptedSeitanV1 struct {
	unixNow  int64
	inviteID SCTeamInviteID
	akey     SeitanAKey
	encoded  string // base64 encoded akey
}

func generateAcceptanceSeitanV1(mctx libkb.MetaContext, ikey SeitanIKey, unixNow int64) (ret acceptedSeitanV1, err error) {
	uv := mctx.CurrentUserVersion()
	if err != nil {
		return ret, err
	}

	sikey, err := ikey.GenerateSIKey()
	if err != nil {
		return ret, err
	}

	inviteID, err := sikey.GenerateTeamInviteID()
	if err != nil {
		return ret, err
	}

	akey, encoded, err := sikey.GenerateAcceptanceKey(uv.Uid, uv.EldestSeqno, unixNow)
	if err != nil {
		return ret, err
	}

	return acceptedSeitanV1{
		unixNow:  unixNow,
		inviteID: inviteID,
		akey:     akey,
		encoded:  encoded,
	}, nil
}

func postSeitanV1(mctx libkb.MetaContext, acceptedSeitan acceptedSeitanV1) error {
	arg := apiArg("team/seitan")
	arg.Args.Add("akey", libkb.S{Val: acceptedSeitan.encoded})
	arg.Args.Add("now", libkb.I64{Val: acceptedSeitan.unixNow})
	arg.Args.Add("invite_id", libkb.S{Val: string(acceptedSeitan.inviteID)})
	_, err := mctx.G().API.Post(mctx, arg)
	return err
}

func parseAndAcceptSeitanTokenV2(ctx context.Context, g *libkb.GlobalContext, tok string) (wasSeitan bool, err error) {
	seitan, err := ParseIKeyV2FromString(tok)
	if err != nil {
		g.Log.CDebugf(ctx, "ParseIKeyV2FromString error: %s", err)
		g.Log.CDebugf(ctx, "returning TeamInviteBadToken instead")
		return false, libkb.TeamInviteBadTokenError{}
	}
	err = AcceptSeitanV2(ctx, g, seitan)
	return true, err

}

func parseAndAcceptSeitanTokenInvitelink(ctx context.Context, g *libkb.GlobalContext, tok string) (wasSeitan bool, err error) {
	seitan, err := ParseIKeyInvitelinkFromString(tok)
	if err != nil {
		g.Log.CDebugf(ctx, "ParseIKeyInvitelinkFromString error: %s", err)
		g.Log.CDebugf(ctx, "returning TeamInviteBadToken instead")
		return false, libkb.TeamInviteBadTokenError{}
	}
	err = AcceptSeitanInvitelink(ctx, g, seitan)
	if err != nil {
		return false, err
	}
	return true, nil

}

func ProcessSeitanV2(ikey SeitanIKeyV2, uv keybase1.UserVersion, kbtime keybase1.Time) (sig string,
	inviteID SCTeamInviteID, err error) {

	sikey, err := ikey.GenerateSIKey()
	if err != nil {
		return sig, inviteID, err
	}

	inviteID, err = sikey.GenerateTeamInviteID()
	if err != nil {
		return sig, inviteID, err
	}

	_, encoded, err := sikey.GenerateSignature(uv.Uid, uv.EldestSeqno, inviteID, kbtime)
	if err != nil {
		return sig, inviteID, err
	}

	return encoded, inviteID, nil
}

func AcceptSeitanV2(ctx context.Context, g *libkb.GlobalContext, ikey SeitanIKeyV2) error {
	mctx := libkb.NewMetaContext(ctx, g)
	uv, err := g.GetMeUV(ctx)
	if err != nil {
		return err
	}

	now := keybase1.ToTime(time.Now())
	encoded, inviteID, err := ProcessSeitanV2(ikey, uv, now)
	if err != nil {
		return err
	}

	g.Log.CDebugf(ctx, "seitan invite ID: %v", inviteID)

	arg := apiArg("team/seitan_v2")
	arg.Args.Add("sig", libkb.S{Val: encoded})
	arg.Args.Add("now", libkb.HTTPTime{Val: now})
	arg.Args.Add("invite_id", libkb.S{Val: string(inviteID)})
	_, err = mctx.G().API.Post(mctx, arg)
	return err
}

func AcceptSeitanInvitelink(ctx context.Context, g *libkb.GlobalContext,
	ikey keybase1.SeitanIKeyInvitelink) error {
	mctx := libkb.NewMetaContext(ctx, g)
	uv, err := g.GetMeUV(ctx)
	if err != nil {
		return err
	}

	sikey, err := GenerateSIKeyInvitelink(ikey)
	if err != nil {
		return err
	}

	inviteID, err := sikey.GenerateTeamInviteID()
	if err != nil {
		return err
	}

	now := time.Now()
	_, encoded, err := GenerateSeitanInvitelinkAcceptanceKey(sikey[:], uv.Uid, uv.EldestSeqno, now.Unix())
	if err != nil {
		return err
	}

	g.Log.CDebugf(ctx, "seitan invite ID: %v", inviteID)

	arg := apiArg("team/seitan_invitelink")
	arg.Args.Add("akey", libkb.S{Val: encoded})
	arg.Args.Add("unix_timestamp", libkb.U{Val: uint64(now.Unix())})
	arg.Args.Add("invite_id", libkb.S{Val: string(inviteID)})
	_, err = mctx.G().API.Post(mctx, arg)
	return err
}
