package channels

import (
	"sync"
	"time"

	"github.com/AZ-X/dns"
)

type State uint32

const (
	STAR               = State(0)          // *
	V1_OK                State = 1 << iota // dns.unpack downstream
	V1_NOK                                 //
	V2_OK                                  // dns.pack
	V2_NOK                                 //
	V3_OK                                  // dns.unpack upstream
	V3_NOK                                 //
	V45_OK                                 // dns.pack outcome
	V4_NOK                                 //
	A1_OK                                  // pre-processing
	A23_OK                                 // post-processing
	CP1_OK                                 // pre-match
	CP1_NOK                                // 
	CP2_OK                                 // post-match
	CP2_NOK                                //
	R_OK                                   // resolving
	R_NOK                                  //
	RCP_NOK                                // failed with cache
	L_OK                                   // logging
	E                                      // E
)

var StateNChannel = map[State]string{
	STAR   :                               Channel_Validation,
	V1_OK  :                               Channel_Amender,
	V1_NOK :                               Channel_Amender,
	V2_OK  :                               Channel_Remote,
	V2_NOK :                               Channel_Amender,
	V3_OK  :                               Channel_CP,
	V3_NOK :                               Channel_Amender,
	V45_OK :                               Channel_Logger,
	V4_NOK :                               Channel_Amender,
	A1_OK  :                               Channel_CP,
	A23_OK :                               Channel_Validation,
	CP1_OK :                               Channel_Validation,
	CP1_NOK:                               Channel_Amender,
	CP2_OK :                               Channel_Amender,
	CP2_NOK:                               Channel_Amender,
	R_OK   :                               Channel_Validation,
	R_NOK  :                               Channel_Amender,
	RCP_NOK:                               Channel_Amender,
	L_OK   :                               Channel_End,
}

// act like self illumination of state flow
type Session struct {
	State
	*dns.Question
	OPTOrigin                              *dns.OPT
	LastState                              State
	RawIn, RawOut                          *[]byte
	Request, Response                      *dns.Msg
	hash_key                               *[32]byte
	ServerName                             *string
	ExtraServerName                        *string // for debug display of 'Anonymized' sever idx
	Listener                               int
	Stopwatch                              time.Time //not started yet
	LastError                              error
	IsUDPClient                            bool
	ID                                     uint16
	rep_job                                *sync.Once
	pl_job                                 *sync.Once
}


