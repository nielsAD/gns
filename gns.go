// Author:  Niels A.D.
// Project: gamenetworkingsockets (https://github.com/nielsAD/gns)
// License: Mozilla Public License, v2.0

// Package gns provides golang bindings for the GameNetworkingSockets library.
package gns

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"sync/atomic"
	"time"
	"unsafe"
)

// #cgo !gns_static LDFLAGS: -lGameNetworkingSockets                             -L${SRCDIR}/lib/GameNetworkingSockets/build/src
// #cgo  gns_static LDFLAGS: -lGameNetworkingSockets_s -lssl -lcrypto -lprotobuf -L${SRCDIR}/lib/GameNetworkingSockets/build/src
/*
	#include <gns.h>

	static inline SteamNetConnectionInfo_t *StatusChangedCallbackInfo_GetInfo(SteamNetConnectionStatusChangedCallback_t *cb) {
		return &cb->m_info;
	}

	void goDebugOutputCallback(ESteamNetworkingSocketsDebugOutputType nType, char *pszMsg);
	void goStatusChangedCallback(SteamNetConnectionStatusChangedCallback_t *pInfo, intptr_t context);
*/
import "C"

// DebugOutputType is the interface to ESteamNetworkingSocketsDebugOutputType
//
// Detail level for diagnostic output callback.
// See ISteamNetworkingUtils::SetDebugOutputFunction
type DebugOutputType C.ESteamNetworkingSocketsDebugOutputType

// DebugOutputType constants
const (
	DebugOutputTypeNone       = C.k_ESteamNetworkingSocketsDebugOutputType_None
	DebugOutputTypeBug        = C.k_ESteamNetworkingSocketsDebugOutputType_Bug       // You used the API incorrectly, or an internal error happened
	DebugOutputTypeError      = C.k_ESteamNetworkingSocketsDebugOutputType_Error     // Run-time error condition that isn't the result of a bug.  (E.g. we are offline, cannot bind a port, etc)
	DebugOutputTypeImportant  = C.k_ESteamNetworkingSocketsDebugOutputType_Important // Nothing is wrong, but this is an important notification
	DebugOutputTypeWarning    = C.k_ESteamNetworkingSocketsDebugOutputType_Warning
	DebugOutputTypeMsg        = C.k_ESteamNetworkingSocketsDebugOutputType_Msg        // Recommended amount
	DebugOutputTypeVerbose    = C.k_ESteamNetworkingSocketsDebugOutputType_Verbose    // Quite a bit
	DebugOutputTypeDebug      = C.k_ESteamNetworkingSocketsDebugOutputType_Debug      // Practically everything
	DebugOutputTypeEverything = C.k_ESteamNetworkingSocketsDebugOutputType_Everything // Wall of text, detailed packet contents breakdown, etc
)

// DebugOutputFunc used for debug callback
type DebugOutputFunc func(typ DebugOutputType, msg string)

var debugOutputCallback DebugOutputFunc

//export goDebugOutputCallback
func goDebugOutputCallback(nType C.ESteamNetworkingSocketsDebugOutputType, pszMsg *C.char) {
	typ := (DebugOutputType)(nType)
	msg := C.GoString(pszMsg)
	debugOutputCallback(typ, msg)
}

// StatusChangedCallbackInfo is the interface to SteamNetConnectionStatusChangedCallback_t
type StatusChangedCallbackInfo = C.SteamNetConnectionStatusChangedCallback_t

// Conn returns m_hConn
func (cb *StatusChangedCallbackInfo) Conn() Connection {
	return (Connection)(cb.m_hConn)
}

// Info returns m_info
func (cb *StatusChangedCallbackInfo) Info() *ConnectionInfo {
	return C.StatusChangedCallbackInfo_GetInfo(cb)
}

// OldState returns m_eOldState
func (cb *StatusChangedCallbackInfo) OldState() ConnectionState {
	return (ConnectionState)(cb.m_eOldState)
}

// StatusChangedCallback function
type StatusChangedCallback func(info *StatusChangedCallbackInfo)

// internal temporary callback function storage
var statusChangedCallbacks [256]StatusChangedCallback

//export goStatusChangedCallback
func goStatusChangedCallback(pInfo *StatusChangedCallbackInfo, context C.intptr_t) {
	statusChangedCallbacks[(int)(context)](pInfo)
}

// ListenSocket is the interface to HSteamListenSocket
//
// Handle used to identify a "listen socket".  Unlike traditional
// Berkeley sockets, a listen socket and a connection are two
// different abstractions.
type ListenSocket C.HSteamListenSocket

// InvalidListenSocket constant
const InvalidListenSocket ListenSocket = C.k_HSteamListenSocket_Invalid

// Connection is the interface to HSteamNetConnection
//
// Handle used to identify a connection to a remote host.
type Connection C.HSteamNetConnection

// InvalidConnection constant
const InvalidConnection Connection = C.k_HSteamNetConnection_Invalid

// PollGroup is the interface to HSteamNetPollGroup
//
// Handle used to identify a poll group, used to query many
// connections at once efficiently.
type PollGroup C.HSteamNetPollGroup

// InvalidPollGroup constant
const InvalidPollGroup PollGroup = C.k_HSteamNetPollGroup_Invalid

// Timestamp is the interface to SteamNetworkingMicroseconds
//
// A local timestamp.  You can subtract two timestamps to get the number of elapsed
// microseconds.  This is guaranteed to increase over time during the lifetime
// of a process, but not globally across runs.  You don't need to worry about
// the value wrapping around.  Note that the underlying clock might not actually have
// microsecond resolution.
type Timestamp C.SteamNetworkingMicroseconds

// ConfigOption is the interface to ESteamNetworkingConfigValue
type ConfigOption C.ESteamNetworkingConfigValue

// ConfigOption constants
const (
	ConfigInvalid ConfigOption = C.k_ESteamNetworkingConfig_Invalid

	// [global float, 0--100] Randomly discard N pct of packets instead of sending/recv
	// This is a global option only, since it is applied at a low level
	// where we don't have much context
	ConfigFakePacketLossSend ConfigOption = C.k_ESteamNetworkingConfig_FakePacketLoss_Send
	ConfigFakePacketLossRecv ConfigOption = C.k_ESteamNetworkingConfig_FakePacketLoss_Recv

	// [global int32].  Delay all outbound/inbound packets by N ms
	ConfigFakePacketLagSend ConfigOption = C.k_ESteamNetworkingConfig_FakePacketLag_Send
	ConfigFakePacketLagRecv ConfigOption = C.k_ESteamNetworkingConfig_FakePacketLag_Recv

	// [global float] 0-100 Percentage of packets we will add additional delay
	// to (causing them to be reordered)
	ConfigFakePacketReorderSend ConfigOption = C.k_ESteamNetworkingConfig_FakePacketReorder_Send
	ConfigFakePacketReorderRecv ConfigOption = C.k_ESteamNetworkingConfig_FakePacketReorder_Recv

	// [global int32] Extra delay, in ms, to apply to reordered packets.
	ConfigFakePacketReorderTime ConfigOption = C.k_ESteamNetworkingConfig_FakePacketReorder_Time

	// [global float 0--100] Globally duplicate some percentage of packets we send
	ConfigFakePacketDupSend ConfigOption = C.k_ESteamNetworkingConfig_FakePacketDup_Send
	ConfigFakePacketDupRecv ConfigOption = C.k_ESteamNetworkingConfig_FakePacketDup_Recv

	// [global int32] Amount of delay, in ms, to delay duplicated packets.
	// (We chose a random delay between 0 and this value)
	ConfigFakePacketDupTimeMax ConfigOption = C.k_ESteamNetworkingConfig_FakePacketDup_TimeMax

	// [connection int32] Timeout value (in ms) to use when first connecting
	ConfigTimeoutInitial ConfigOption = C.k_ESteamNetworkingConfig_TimeoutInitial

	// [connection int32] Timeout value (in ms) to use after connection is established
	ConfigTimeoutConnected ConfigOption = C.k_ESteamNetworkingConfig_TimeoutConnected

	// [connection int32] Upper limit of buffered pending bytes to be sent
	// if this is reached SendMessage will return k_EResultLimitExceeded
	// Default is 512k (524288 bytes)
	ConfigSendBufferSize ConfigOption = C.k_ESteamNetworkingConfig_SendBufferSize

	// [connection int32] Minimum/maximum send rate clamp, 0 is no limit.
	// This value will control the min/max allowed sending rate that
	// bandwidth estimation is allowed to reach.  Default is 0 (no-limit)
	ConfigSendRateMin ConfigOption = C.k_ESteamNetworkingConfig_SendRateMin
	ConfigSendRateMax ConfigOption = C.k_ESteamNetworkingConfig_SendRateMax

	// [connection int32] Nagle time, in microseconds.  When SendMessage is called, if
	// the outgoing message is less than the size of the MTU, it will be
	// queued for a delay equal to the Nagle timer value.  This is to ensure
	// that if the application sends several small messages rapidly, they are
	// coalesced into a single packet.
	// See historical RFC 896.  Value is in microseconds.
	// Default is 5000us (5ms).
	ConfigNagleTime ConfigOption = C.k_ESteamNetworkingConfig_NagleTime

	// [connection int32] Don't automatically fail IP connections that don't have
	// strong auth.  On clients, this means we will attempt the connection even if
	// we don't know our identity or can't get a cert.  On the server, it means that
	// we won't automatically reject a connection due to a failure to authenticate.
	// (You can examine the incoming connection and decide whether to accept it.)
	//
	// This is a dev configuration value, and you should not let users modify it in
	// production.
	ConfigIPAllowWithoutAuth ConfigOption = C.k_ESteamNetworkingConfig_IP_AllowWithoutAuth

	// [connection int32] Do not send UDP packets with a payload of
	// larger than N bytes.  If you set this, k_ESteamNetworkingConfig_MTU_DataSize
	// is automatically adjusted
	ConfigMTUPacketSize ConfigOption = C.k_ESteamNetworkingConfig_MTU_PacketSize

	// [connection int32] (read only) Maximum message size you can send that
	// will not fragment, based on k_ESteamNetworkingConfig_MTU_PacketSize
	ConfigMTUDataSize ConfigOption = C.k_ESteamNetworkingConfig_MTU_DataSize

	// [connection int32] Allow unencrypted (and unauthenticated) communication.
	// 0: Not allowed (the default)
	// 1: Allowed, but prefer encrypted
	// 2: Allowed, and preferred
	// 3: Required.  (Fail the connection if the peer requires encryption.)
	//
	// This is a dev configuration value, since its purpose is to disable encryption.
	// You should not let users modify it in production.  (But note that it requires
	// the peer to also modify their value in order for encryption to be disabled.)
	ConfigUnencrypted ConfigOption = C.k_ESteamNetworkingConfig_Unencrypted

	// [global int32] 0 or 1.  Some variables are "dev" variables.  They are useful
	// for debugging, but should not be adjusted in production.  When this flag is false (the default)
	// such variables will not be enumerated by the ISteamnetworkingUtils::GetFirstConfigValue
	// ISteamNetworkingUtils::GetConfigValueInfo functions.  The idea here is that you
	// can use those functions to provide a generic mechanism to set any configuration
	// value from a console or configuration file, looking up the variable by name.  Depending
	// on your game, modifying other configuration values may also have negative effects, and
	// you may wish to further lock down which variables are allowed to be modified by the user.
	// (Maybe no variables!)  Or maybe you use a whitelist or blacklist approach.
	//
	// (This flag is itself a dev variable.)
	ConfigEnumerateDevVars ConfigOption = C.k_ESteamNetworkingConfig_EnumerateDevVars

	//
	// Log levels for debuging information.  A higher priority
	// (lower numeric value) will cause more stuff to be printed.
	//
	ConfigLogLevelAckRTT        ConfigOption = C.k_ESteamNetworkingConfig_LogLevel_AckRTT        // [connection int32] RTT calculations for inline pings and replies
	ConfigLogLevelPacketDecode  ConfigOption = C.k_ESteamNetworkingConfig_LogLevel_PacketDecode  // [connection int32] log SNP packets send
	ConfigLogLevelMessage       ConfigOption = C.k_ESteamNetworkingConfig_LogLevel_Message       // [connection int32] log each message send/recv
	ConfigLogLevelPacketGaps    ConfigOption = C.k_ESteamNetworkingConfig_LogLevel_PacketGaps    // [connection int32] dropped packets
	ConfigLogLevelP2PRendezvous ConfigOption = C.k_ESteamNetworkingConfig_LogLevel_P2PRendezvous // [connection int32] P2P rendezvous messages
)

// ConfigType is the interface to ESteamNetworkingConfigDataType
type ConfigType C.ESteamNetworkingConfigDataType

// ConfigType constants
const (
	ConfigTypeInt32       ConfigType = C.k_ESteamNetworkingConfig_Int32
	ConfigTypeInt64       ConfigType = C.k_ESteamNetworkingConfig_Int64
	ConfigTypeFloat       ConfigType = C.k_ESteamNetworkingConfig_Float
	ConfigTypeString      ConfigType = C.k_ESteamNetworkingConfig_String
	ConfigTypeFunctionPtr ConfigType = C.k_ESteamNetworkingConfig_FunctionPtr // NOTE: When setting	callbacks, you should put the pointer into a variable and pass a pointer to that variable.
)

// ConfigValue is the interface to SteamNetworkingConfigValue_t
//
// In a few places we need to set configuration options on listen sockets and connections, and
// have them take effect *before* the listen socket or connection really starts doing anything.
// Creating the object and then setting the options "immediately" after creation doesn't work
// completely, because network packets could be received between the time the object is created and
// when the options are applied.  To set options at creation time in a reliable way, they must be
// passed to the creation function.  This structure is used to pass those options.
//
// For the meaning of these fields, see ISteamNetworkingUtils::SetConfigValue.  Basically
// when the object is created, we just iterate over the list of options and call
// ISteamNetworkingUtils::SetConfigValueStruct, where the scope arguments are supplied by the
// object being created.
type ConfigValue = C.SteamNetworkingConfigValue_t

// NewConfigValue maps interface{} to ConfigValue
func NewConfigValue(opt ConfigOption, val interface{}) *ConfigValue {
	var res ConfigValue
	res.m_eValue = C.ESteamNetworkingConfigValue(opt)

	switch v := val.(type) {
	case int:
		res.m_eDataType = (C.ESteamNetworkingConfigDataType)(ConfigTypeInt32)
		*(*C.int32_t)(unsafe.Pointer(&res.m_val)) = C.int32_t(v)
	case int32:
		res.m_eDataType = (C.ESteamNetworkingConfigDataType)(ConfigTypeInt32)
		*(*C.int32_t)(unsafe.Pointer(&res.m_val)) = C.int32_t(v)
	case int64:
		res.m_eDataType = (C.ESteamNetworkingConfigDataType)(ConfigTypeInt64)
		*(*C.int64_t)(unsafe.Pointer(&res.m_val)) = C.int64_t(v)
	case float32:
		res.m_eDataType = (C.ESteamNetworkingConfigDataType)(ConfigTypeFloat)
		*(*C.float)(unsafe.Pointer(&res.m_val)) = C.float(v)
	case float64:
		res.m_eDataType = (C.ESteamNetworkingConfigDataType)(ConfigTypeFloat)
		*(*C.float)(unsafe.Pointer(&res.m_val)) = C.float(v)
	default:
		panic("gns: Unsupported ConfigValue type")
	}

	return &res
}

// Val return go type
func (cfg *ConfigValue) Val() interface{} {
	switch cfg.Type() {
	case ConfigTypeInt32:
		return cfg.Int32()
	case ConfigTypeInt64:
		return cfg.Int64()
	case ConfigTypeFloat:
		return cfg.Float()
	case ConfigTypeString:
		return cfg.String()
	default:
		panic("gns: Unsupported ConfigValue type")
	}
}

// Type returns m_eDataType
func (cfg *ConfigValue) Type() ConfigType { return (ConfigType)(cfg.m_eDataType) }

// Int32 returns m_int32
func (cfg *ConfigValue) Int32() int32 { return int32(*(*C.int32_t)(unsafe.Pointer(&cfg.m_val))) }

// Int64 returns m_int64
func (cfg *ConfigValue) Int64() int64 { return int64(*(*C.int64_t)(unsafe.Pointer(&cfg.m_val))) }

// Float returns m_float
func (cfg *ConfigValue) Float() float32 { return float32(*(*C.float)(unsafe.Pointer(&cfg.m_val))) }

// Strings returns m_string
func (cfg *ConfigValue) String() string { return C.GoString((*C.char)(unsafe.Pointer(&cfg.m_val))) }

// ConfigMap convencience type
type ConfigMap map[ConfigOption]interface{}

func (m ConfigMap) pack() []C.SteamNetworkingConfigValue_t {
	var res []C.SteamNetworkingConfigValue_t
	for k, v := range m {
		val := NewConfigValue(k, v)
		res = append(res, (C.SteamNetworkingConfigValue_t)(*val))
	}
	return res
}

// Result is the interface to EResult
type Result C.EResult

func (r Result) Error() string {
	switch r {
	case ResultInvalidParam:
		return "gns: EResultInvalidParam"
	case ResultInvalidState:
		return "gns: EResultInvalidState"
	case ResultNoConnection:
		return "gns: EResultNoConnection"
	case ResultIgnored:
		return "gns: EResultIgnored"
	case ResultLimitExceeded:
		return "gns: EResultLimitExceeded"
	default:
		return fmt.Sprintf("gns: EResult[%d]", int(r))
	}
}

// Result constants
const (
	ResultOK                                      Result = C.k_EResultOK                    // success
	ResultFail                                    Result = C.k_EResultFail                  // generic failure
	ResultNoConnection                            Result = C.k_EResultNoConnection          // no/failed network connection
	ResultInvalidPassword                         Result = C.k_EResultInvalidPassword       // password/ticket is invalid
	ResultLoggedInElsewhere                       Result = C.k_EResultLoggedInElsewhere     // same user logged in elsewhere
	ResultInvalidProtocolVer                      Result = C.k_EResultInvalidProtocolVer    // protocol version is incorrect
	ResultInvalidParam                            Result = C.k_EResultInvalidParam          // a parameter is incorrect
	ResultFileNotFound                            Result = C.k_EResultFileNotFound          // file was not found
	ResultBusy                                    Result = C.k_EResultBusy                  // called method busy - action not taken
	ResultInvalidState                            Result = C.k_EResultInvalidState          // called object was in an invalid state
	ResultInvalidName                             Result = C.k_EResultInvalidName           // name is invalid
	ResultInvalidEmail                            Result = C.k_EResultInvalidEmail          // email is invalid
	ResultDuplicateName                           Result = C.k_EResultDuplicateName         // name is not unique
	ResultAccessDenied                            Result = C.k_EResultAccessDenied          // access is denied
	ResultTimeout                                 Result = C.k_EResultTimeout               // operation timed out
	ResultBanned                                  Result = C.k_EResultBanned                // VAC2 banned
	ResultAccountNotFound                         Result = C.k_EResultAccountNotFound       // account not found
	ResultInvalidSteamID                          Result = C.k_EResultInvalidSteamID        // steamID is invalid
	ResultServiceUnavailable                      Result = C.k_EResultServiceUnavailable    // The requested service is currently unavailable
	ResultNotLoggedOn                             Result = C.k_EResultNotLoggedOn           // The user is not logged on
	ResultPending                                 Result = C.k_EResultPending               // Request is pending (may be in process, or waiting on third party)
	ResultEncryptionFailure                       Result = C.k_EResultEncryptionFailure     // Encryption or Decryption failed
	ResultInsufficientPrivilege                   Result = C.k_EResultInsufficientPrivilege // Insufficient privilege
	ResultLimitExceeded                           Result = C.k_EResultLimitExceeded         // Too much of a good thing
	ResultRevoked                                 Result = C.k_EResultRevoked               // Access has been revoked (used for revoked guest passes)
	ResultExpired                                 Result = C.k_EResultExpired               // License/Guest pass the user is trying to access is expired
	ResultAlreadyRedeemed                         Result = C.k_EResultAlreadyRedeemed       // Guest pass has already been redeemed by account, cannot be acked again
	ResultDuplicateRequest                        Result = C.k_EResultDuplicateRequest      // The request is a duplicate and the action has already occurred in the past, ignored this time
	ResultAlreadyOwned                            Result = C.k_EResultAlreadyOwned          // All the games in this guest pass redemption request are already owned by the user
	ResultIPNotFound                              Result = C.k_EResultIPNotFound            // IP address not found
	ResultPersistFailed                           Result = C.k_EResultPersistFailed         // failed to write change to the data store
	ResultLockingFailed                           Result = C.k_EResultLockingFailed         // failed to acquire access lock for this operation
	ResultLogonSessionReplaced                    Result = C.k_EResultLogonSessionReplaced
	ResultConnectFailed                           Result = C.k_EResultConnectFailed
	ResultHandshakeFailed                         Result = C.k_EResultHandshakeFailed
	ResultIOFailure                               Result = C.k_EResultIOFailure
	ResultRemoteDisconnect                        Result = C.k_EResultRemoteDisconnect
	ResultShoppingCartNotFound                    Result = C.k_EResultShoppingCartNotFound // failed to find the shopping cart requested
	ResultBlocked                                 Result = C.k_EResultBlocked              // a user didn't allow it
	ResultIgnored                                 Result = C.k_EResultIgnored              // target is ignoring sender
	ResultNoMatch                                 Result = C.k_EResultNoMatch              // nothing matching the request found
	ResultAccountDisabled                         Result = C.k_EResultAccountDisabled
	ResultServiceReadOnly                         Result = C.k_EResultServiceReadOnly               // this service is not accepting content changes right now
	ResultAccountNotFeatured                      Result = C.k_EResultAccountNotFeatured            // account doesn't have value, so this feature isn't available
	ResultAdministratorOK                         Result = C.k_EResultAdministratorOK               // allowed to take this action, but only because requester is admin
	ResultContentVersion                          Result = C.k_EResultContentVersion                // A Version mismatch in content transmitted within the Steam protocol.
	ResultTryAnotherCM                            Result = C.k_EResultTryAnotherCM                  // The current CM can't service the user making a request, user should try another.
	ResultPasswordRequiredToKickSession           Result = C.k_EResultPasswordRequiredToKickSession // You are already logged in elsewhere, this cached credential login has failed.
	ResultAlreadyLoggedInElsewhere                Result = C.k_EResultAlreadyLoggedInElsewhere      // You are already logged in elsewhere, you must wait
	ResultSuspended                               Result = C.k_EResultSuspended                     // Long running operation (content download) suspended/paused
	ResultCancelled                               Result = C.k_EResultCancelled                     // Operation canceled (typically by user: content download)
	ResultDataCorruption                          Result = C.k_EResultDataCorruption                // Operation canceled because data is ill formed or unrecoverable
	ResultDiskFull                                Result = C.k_EResultDiskFull                      // Operation canceled - not enough disk space.
	ResultRemoteCallFailed                        Result = C.k_EResultRemoteCallFailed              // an remote call or IPC call failed
	ResultPasswordUnset                           Result = C.k_EResultPasswordUnset                 // Password could not be verified as it's unset server side
	ResultExternalAccountUnlinked                 Result = C.k_EResultExternalAccountUnlinked       // External account (PSN, Facebook...) is not linked to a Steam account
	ResultPSNTicketInvalid                        Result = C.k_EResultPSNTicketInvalid              // PSN ticket was invalid
	ResultExternalAccountAlreadyLinked            Result = C.k_EResultExternalAccountAlreadyLinked  // External account (PSN, Facebook...) is already linked to some other account, must explicitly request to replace/delete the link first
	ResultRemoteFileConflict                      Result = C.k_EResultRemoteFileConflict            // The sync cannot resume due to a conflict between the local and remote files
	ResultIllegalPassword                         Result = C.k_EResultIllegalPassword               // The requested new password is not legal
	ResultSameAsPreviousValue                     Result = C.k_EResultSameAsPreviousValue           // new value is the same as the old one ( secret question and answer )
	ResultAccountLogonDenied                      Result = C.k_EResultAccountLogonDenied            // account login denied due to 2nd factor authentication failure
	ResultCannotUseOldPassword                    Result = C.k_EResultCannotUseOldPassword          // The requested new password is not legal
	ResultInvalidLoginAuthCode                    Result = C.k_EResultInvalidLoginAuthCode          // account login denied due to auth code invalid
	ResultAccountLogonDeniedNoMail                Result = C.k_EResultAccountLogonDeniedNoMail      // account login denied due to 2nd factor auth failure - and no mail has been sent
	ResultHardwareNotCapableOfIPT                 Result = C.k_EResultHardwareNotCapableOfIPT       //
	ResultIPTInitError                            Result = C.k_EResultIPTInitError                  //
	ResultParentalControlRestricted               Result = C.k_EResultParentalControlRestricted     // operation failed due to parental control restrictions for current user
	ResultFacebookQueryError                      Result = C.k_EResultFacebookQueryError            // Facebook query returned an error
	ResultExpiredLoginAuthCode                    Result = C.k_EResultExpiredLoginAuthCode          // account login denied due to auth code expired
	ResultIPLoginRestrictionFailed                Result = C.k_EResultIPLoginRestrictionFailed
	ResultAccountLockedDown                       Result = C.k_EResultAccountLockedDown
	ResultAccountLogonDeniedVerifiedEmailRequired Result = C.k_EResultAccountLogonDeniedVerifiedEmailRequired
	ResultNoMatchingURL                           Result = C.k_EResultNoMatchingURL
	ResultBadResponse                             Result = C.k_EResultBadResponse                         // parse failure, missing field, etc.
	ResultRequirePasswordReEntry                  Result = C.k_EResultRequirePasswordReEntry              // The user cannot complete the action until they re-enter their password
	ResultValueOutOfRange                         Result = C.k_EResultValueOutOfRange                     // the value entered is outside the acceptable range
	ResultUnexpectedError                         Result = C.k_EResultUnexpectedError                     // something happened that we didn't expect to ever happen
	ResultDisabled                                Result = C.k_EResultDisabled                            // The requested service has been configured to be unavailable
	ResultInvalidCEGSubmission                    Result = C.k_EResultInvalidCEGSubmission                // The set of files submitted to the CEG server are not valid !
	ResultRestrictedDevice                        Result = C.k_EResultRestrictedDevice                    // The device being used is not allowed to perform this action
	ResultRegionLocked                            Result = C.k_EResultRegionLocked                        // The action could not be complete because it is region restricted
	ResultRateLimitExceeded                       Result = C.k_EResultRateLimitExceeded                   // Temporary rate limit exceeded, try again later, different from k_EResultLimitExceeded which may be permanent
	ResultAccountLoginDeniedNeedTwoFactor         Result = C.k_EResultAccountLoginDeniedNeedTwoFactor     // Need two-factor code to login
	ResultItemDeleted                             Result = C.k_EResultItemDeleted                         // The thing we're trying to access has been deleted
	ResultAccountLoginDeniedThrottle              Result = C.k_EResultAccountLoginDeniedThrottle          // login attempt failed, try to throttle response to possible attacker
	ResultTwoFactorCodeMismatch                   Result = C.k_EResultTwoFactorCodeMismatch               // two factor code mismatch
	ResultTwoFactorActivationCodeMismatch         Result = C.k_EResultTwoFactorActivationCodeMismatch     // activation code for two-factor didn't match
	ResultAccountAssociatedToMultiplePartners     Result = C.k_EResultAccountAssociatedToMultiplePartners // account has been associated with multiple partners
	ResultNotModified                             Result = C.k_EResultNotModified                         // data not modified
	ResultNoMobileDevice                          Result = C.k_EResultNoMobileDevice                      // the account does not have a mobile device associated with it
	ResultTimeNotSynced                           Result = C.k_EResultTimeNotSynced                       // the time presented is out of range or tolerance
	ResultSmsCodeFailed                           Result = C.k_EResultSmsCodeFailed                       // SMS code failure (no match, none pending, etc.)
	ResultAccountLimitExceeded                    Result = C.k_EResultAccountLimitExceeded                // Too many accounts access this resource
	ResultAccountActivityLimitExceeded            Result = C.k_EResultAccountActivityLimitExceeded        // Too many changes to this account
	ResultPhoneActivityLimitExceeded              Result = C.k_EResultPhoneActivityLimitExceeded          // Too many changes to this phone
	ResultRefundToWallet                          Result = C.k_EResultRefundToWallet                      // Cannot refund to payment method, must use wallet
	ResultEmailSendFailure                        Result = C.k_EResultEmailSendFailure                    // Cannot send an email
	ResultNotSettled                              Result = C.k_EResultNotSettled                          // Can't perform operation till payment has settled
	ResultNeedCaptcha                             Result = C.k_EResultNeedCaptcha                         // Needs to provide a valid captcha
	ResultGSLTDenied                              Result = C.k_EResultGSLTDenied                          // a game server login token owned by this token's owner has been banned
	ResultGSOwnerDenied                           Result = C.k_EResultGSOwnerDenied                       // game server owner is denied for other reason (account lock, community ban, vac ban, missing phone)
	ResultInvalidItemType                         Result = C.k_EResultInvalidItemType                     // the type of thing we were requested to act on is invalid
	ResultIPBanned                                Result = C.k_EResultIPBanned                            // the ip address has been banned from taking this action
	ResultGSLTExpired                             Result = C.k_EResultGSLTExpired                         // this token has expired from disuse; can be reset for use
	ResultInsufficientFunds                       Result = C.k_EResultInsufficientFunds                   // user doesn't have enough wallet funds to complete the action
	ResultTooManyPending                          Result = C.k_EResultTooManyPending                      // There are too many of this thing pending already
	ResultNoSiteLicensesFound                     Result = C.k_EResultNoSiteLicensesFound                 // No site licenses found
	ResultWGNetworkSendExceeded                   Result = C.k_EResultWGNetworkSendExceeded               // the WG couldn't send a response because we exceeded max network send size
)

// IdentityType is the interface to ESteamNetworkingIdentityType
type IdentityType C.ESteamNetworkingIdentityType

// IdentityType constants
const (
	// Dummy/empty/invalid.
	// Plese note that if we parse a string that we don't recognize
	// but that appears reasonable, we will NOT use this type.  Instead
	// we'll use k_ESteamNetworkingIdentityType_UnknownType.
	IdentityTypeInvalid IdentityType = C.k_ESteamNetworkingIdentityType_Invalid

	//
	// Basic platform-specific identifiers.
	//
	IdentityTypeSteamID IdentityType = C.k_ESteamNetworkingIdentityType_SteamID // 64-bit CSteamID

	//
	// Special identifiers.
	//

	// Use their IP address (and port) as their "identity".
	// These types of identities are always unauthenticated.
	// They are useful for porting plain sockets code, and other
	// situations where you don't care about authentication.  In this
	// case, the local identity will be "localhost",
	// and the remote address will be their network address.
	//
	// We use the same type for either IPv4 or IPv6, and
	// the address is always store as IPv6.  We use IPv4
	// mapped addresses to handle IPv4.
	IdentityTypeIPAddress IdentityType = C.k_ESteamNetworkingIdentityType_IPAddress

	// Generic string/binary blobs.  It's up to your app to interpret this.
	// This library can tell you if the remote host presented a certificate
	// signed by somebody you have chosen to trust, with this identity on it.
	// It's up to you to ultimately decide what this identity means.
	IdentityTypeGenericString IdentityType = C.k_ESteamNetworkingIdentityType_GenericString
	IdentityTypeGenericBytes  IdentityType = C.k_ESteamNetworkingIdentityType_GenericBytes

	// This identity type is used when we parse a string that looks like is a
	// valid identity, just of a kind that we don't recognize.  In this case, we
	// can often still communicate with the peer!  Allowing such identities
	// for types we do not recognize useful is very useful for forward
	// compatibility.
	IdentityTypeUnknownType IdentityType = C.k_ESteamNetworkingIdentityType_UnknownType
)

// Identity is the interface to SteamNetworkingIdentity
//
// An abstract way to represent the identity of a network host.  All identities can
// be represented as simple string.  Furthermore, this string representation is actually
// used on the wire in several places, even though it is less efficient, in order to
// facilitate forward compatibility.  (Old client code can handle an identity type that
// it doesn't understand.)
type Identity = C.SteamNetworkingIdentity

// ParseIdentity is the interface to SteamNetworkingIdentity::ParseString
//
// Parse back a string that was generated using ToString.  If we don't understand the
// string, but it looks "reasonable" (it matches the pattern type:<type-data> and doesn't
// have any funky characters, etc), then we will return true, and the type is set to
// k_ESteamNetworkingIdentityType_UnknownType.  false will only be returned if the string
// looks invalid.
func ParseIdentity(id string) *Identity {
	str := C.CString(id)
	defer C.free(unsafe.Pointer(str))

	var res Identity
	if C.SteamAPI_SteamNetworkingIdentity_ParseString(&res, (C.size_t)(unsafe.Sizeof(res)), str) {
		return &res
	}

	return nil
}

// Valid is the interface to SteamNetworkingIdentity::IsInvalid
//
// Return false if we are the invalid type.  Does not make any other validity checks (e.g. is SteamID actually valid)
func (id *Identity) Valid() bool {
	return id != nil && !(bool)(C.SteamAPI_SteamNetworkingIdentity_IsInvalid(id))
}

// Equals is the interface to SteamNetworkingIdentity::IsEqualTo
//
// See if two identities are identical.
func (id *Identity) Equals(other *Identity) bool {
	return (bool)(C.SteamAPI_SteamNetworkingIdentity_IsEqualTo(id, other))
}

// Valid is the interface to SteamNetworkingIdentity::ToString
//
// Print to a human-readable string.  This is suitable for debug messages
// or any other time you need to encode the identity as a string.  It has a
// URL-like format (type:<type-data>).  Your buffer should be at least
// k_cchMaxString bytes big to avoid truncation.
func (id *Identity) String() string {
	var buf [C.k_cchSteamNetworkingIdentityMaxString]C.char
	C.SteamAPI_SteamNetworkingIdentity_ToString(id, &buf[0], (C.size_t)(len(buf)))
	return C.GoString(&buf[0])
}

// Type returns m_eDataType
func (id *Identity) Type() IdentityType { return (IdentityType)(id.m_eType) }

// IPAddr is the interface to SteamNetworkingIPAddr
//
// Store an IP and port.  IPv6 is always used; IPv4 is represented using
// "IPv4-mapped" addresses: IPv4 aa.bb.cc.dd => IPv6 ::ffff:aabb:ccdd
// (RFC 4291 section 2.5.5.2.)
type IPAddr = C.SteamNetworkingIPAddr

// NewIPAddr maps net.UDPAddr to IPAddr
func NewIPAddr(addr *net.UDPAddr) *IPAddr {
	port := (C.uint16_t)(addr.Port)

	var res IPAddr
	C.SteamAPI_SteamNetworkingIPAddr_Clear(&res)
	if ip4 := addr.IP.To4(); ip4 != nil {
		C.SteamAPI_SteamNetworkingIPAddr_SetIPv4(&res, (C.uint32_t)(binary.BigEndian.Uint32(ip4)), port)
	} else if ip16 := addr.IP.To16(); ip16 != nil {
		C.SteamAPI_SteamNetworkingIPAddr_SetIPv6(&res, (*C.uint8_t)(&ip16[0]), port)
	} else {
		C.SteamAPI_SteamNetworkingIPAddr_Clear(&res)
	}

	return &res
}

// UDPAddr returns the corresponding net.UDPAddr
func (addr *IPAddr) UDPAddr() *net.UDPAddr {
	ip := make(net.IP, net.IPv6len)
	copy(ip, addr.m_ip[:])

	return &net.UDPAddr{
		IP:   ip,
		Port: int(addr.m_port),
	}
}

// SendFlags used to set options for message sending
type SendFlags int

// SendFlags constants
const (
	// Send the message unreliably. Can be lost.  Messages *can* be larger than a
	// single MTU (UDP packet), but there is no retransmission, so if any piece
	// of the message is lost, the entire message will be dropped.
	//
	// The sending API does have some knowledge of the underlying connection, so
	// if there is no NAT-traversal accomplished or there is a recognized adjustment
	// happening on the connection, the packet will be batched until the connection
	// is open again.
	//
	// Migration note: This is not exactly the same as k_EP2PSendUnreliable!  You
	// probably want k_ESteamNetworkingSendType_UnreliableNoNagle
	SendUnreliable SendFlags = C.k_nSteamNetworkingSend_Unreliable

	// Disable Nagle's algorithm.
	// By default, Nagle's algorithm is applied to all outbound messages.  This means
	// that the message will NOT be sent immediately, in case further messages are
	// sent soon after you send this, which can be grouped together.  Any time there
	// is enough buffered data to fill a packet, the packets will be pushed out immediately,
	// but partially-full packets not be sent until the Nagle timer expires.  See
	// ISteamNetworkingSockets::FlushMessagesOnConnection, ISteamNetworkingMessages::FlushMessagesToUser
	//
	// NOTE: Don't just send every message without Nagle because you want packets to get there
	// quicker.  Make sure you understand the problem that Nagle is solving before disabling it.
	// If you are sending small messages, often many at the same time, then it is very likely that
	// it will be more efficient to leave Nagle enabled.  A typical proper use of this flag is
	// when you are sending what you know will be the last message sent for a while (e.g. the last
	// in the server simulation tick to a particular client), and you use this flag to flush all
	// messages.
	SendNoNagle SendFlags = C.k_nSteamNetworkingSend_NoNagle

	// Send a message unreliably, bypassing Nagle's algorithm for this message and any messages
	// currently pending on the Nagle timer.  This is equivalent to using k_ESteamNetworkingSend_Unreliable
	// and then immediately flushing the messages using ISteamNetworkingSockets::FlushMessagesOnConnection
	// or ISteamNetworkingMessages::FlushMessagesToUser.  (But using this flag is more efficient since you
	// only make one API call.)
	SendUnreliableNoNagle SendFlags = C.k_nSteamNetworkingSend_UnreliableNoNagle

	// If the message cannot be sent very soon (because the connection is still doing some initial
	// handshaking, route negotiations, etc), then just drop it.  This is only applicable for unreliable
	// messages.  Using this flag on reliable messages is invalid.
	SendNoDelay SendFlags = C.k_nSteamNetworkingSend_NoDelay

	// Send an unreliable message, but if it cannot be sent relatively quickly, just drop it instead of queuing it.
	// This is useful for messages that are not useful if they are excessively delayed, such as voice data.
	// NOTE: The Nagle algorithm is not used, and if the message is not dropped, any messages waiting on the
	// Nagle timer are immediately flushed.
	//
	// A message will be dropped under the following circumstances:
	// - the connection is not fully connected.  (E.g. the "Connecting" or "FindingRoute" states)
	// - there is a sufficiently large number of messages queued up already such that the current message
	//   will not be placed on the wire in the next ~200ms or so.
	//
	// If a message is dropped for these reasons, k_EResultIgnored will be returned.
	SendUnreliableNoDelay SendFlags = C.k_nSteamNetworkingSend_UnreliableNoDelay

	// Reliable message send. Can send up to k_cbMaxSteamNetworkingSocketsMessageSizeSend bytes in a single message.
	// Does fragmentation/re-assembly of messages under the hood, as well as a sliding window for
	// efficient sends of large chunks of data.
	//
	// The Nagle algorithm is used.  See notes on k_ESteamNetworkingSendType_Unreliable for more details.
	// See k_ESteamNetworkingSendType_ReliableNoNagle, ISteamNetworkingSockets::FlushMessagesOnConnection,
	// ISteamNetworkingMessages::FlushMessagesToUser
	//
	// Migration note: This is NOT the same as k_EP2PSendReliable, it's more like k_EP2PSendReliableWithBuffering
	SendReliable SendFlags = C.k_nSteamNetworkingSend_Reliable

	// Send a message reliably, but bypass Nagle's algorithm.
	//
	// Migration note: This is equivalent to k_EP2PSendReliable
	SendReliableNoNagle SendFlags = C.k_nSteamNetworkingSend_ReliableNoNagle

	// By default, message sending is queued, and the work of encryption and talking to
	// the operating system sockets, etc is done on a service thread.  This is usually a
	// a performance win when messages are sent from the "main thread".  However, if this
	// flag is set, and data is ready to be sent immediately (either from this message
	// or earlier queued data), then that work will be done in the current thread, before
	// the current call returns.  If data is not ready to be sent (due to rate limiting
	// or Nagle), then this flag has no effect.
	//
	// This is an advanced flag used to control performance at a very low level.  For
	// most applications running on modern hardware with more than one CPU core, doing
	// the work of sending on a service thread will yield the best performance.  Only
	// use this flag if you have a really good reason and understand what you are doing.
	// Otherwise you will probably just make performance worse.
	SendUseCurrentThread SendFlags = C.k_nSteamNetworkingSend_UseCurrentThread
)

// Message constants
const (
	// Max size of a single message that we can SEND.
	MaxMessageSizeSend = C.k_cbMaxSteamNetworkingSocketsMessageSizeSend

	// Max size of a message that we are wiling to *receive*.
	MaxMessageSizeRecv = C.k_cbMaxMessageSizeRecv
)

// Message is the interface to SteamNetworkingMessage_t
//
// A message that has been received.
type Message = C.SteamNetworkingMessage_t

// Release is the interface to SteamNetworkingMessage_t::Release
//
// You MUST call this when you're done with the object,
// to free up memory, etc.
func (msg *Message) Release() {
	C.SteamAPI_SteamNetworkingMessage_t_Release(msg)
}

// Payload returns m_pData
func (msg *Message) Payload() []byte {
	return (*[1 << 31]byte)(msg.m_pData)[:msg.m_cbSize:msg.m_cbSize]
}

// Size returns m_cbSize
//
// Size of the payload.
func (msg *Message) Size() int { return (int)(msg.m_cbSize) }

// Conn returns m_conn
//
// For messages received on connections: what connection did this come from?
// For outgoing messages: what connection to send it to?
// Not used when using the ISteamNetworkingMessages interface
func (msg *Message) Conn() Connection { return (Connection)(msg.m_conn) }

// PeerIdentity returns m_identityPeer
//
// For messages received on connections: what connection did this come from?
// For outgoing messages: what connection to send it to?
// Not used when using the ISteamNetworkingMessages interface
func (msg *Message) PeerIdentity() *Identity { return &msg.m_identityPeer }

// UserData returns m_m_nConnUserDataconn
//
// For messages received on connections, this is the user data
// associated with the connection.
//
// This is *usually* the same as calling GetConnection() and then
// fetching the user data associated with that connection, but for
// the following subtle differences:
//
//  - This user data will match the connection's user data at the time
//    is captured at the time the message is returned by the API.
//    If you subsequently change the userdata on the connection,
//    this won't be updated.
//  - This is an inline call, so it's *much* faster.
//  - You might have closed the connection, so fetching the user data
//   would not be possible.
//
// Not used when sending messages,
func (msg *Message) UserData() int64 { return (int64)(msg.m_nConnUserData) }

// Timestamp returns m_usecTimeReceived
//
// Local timestamp when the message was received
// Not used for outbound messages.
func (msg *Message) Timestamp() Timestamp { return (Timestamp)(msg.m_usecTimeReceived) }

// MessageNumber returns m_nMessageNumber
//
// Message number assigned by the sender.
// This is not used for outbound messages
func (msg *Message) MessageNumber() int64 { return (int64)(msg.m_nMessageNumber) }

// Flags returns m_nFlags
//
// Bitmask of k_nSteamNetworkingSend_xxx flags.
// For received messages, only the k_nSteamNetworkingSend_Reliable bit is valid.
// For outbound messages, all bits are relevant
func (msg *Message) Flags() SendFlags { return (SendFlags)(msg.m_nFlags) }

// ConnectionState is the interface to ESteamNetworkingConnectionState
//
// High level connection status
type ConnectionState C.ESteamNetworkingConnectionState

// ConnectionState constants
const (
	// Dummy value used to indicate an error condition in the API.
	// Specified connection doesn't exist or has already been closed.
	ConnectionStateNone ConnectionState = C.k_ESteamNetworkingConnectionState_None

	// We are trying to establish whether peers can talk to each other,
	// whether they WANT to talk to each other, perform basic auth,
	// and exchange crypt keys.
	//
	// - For connections on the "client" side (initiated locally):
	//   We're in the process of trying to establish a connection.
	//   Depending on the connection type, we might not know who they are.
	//   Note that it is not possible to tell if we are waiting on the
	//   network to complete handshake packets, or for the application layer
	//   to accept the connection.
	//
	// - For connections on the "server" side (accepted through listen socket):
	//   We have completed some basic handshake and the client has presented
	//   some proof of identity.  The connection is ready to be accepted
	//   using AcceptConnection().
	//
	// In either case, any unreliable packets sent now are almost certain
	// to be dropped.  Attempts to receive packets are guaranteed to fail.
	// You may send messages if the send mode allows for them to be queued.
	// but if you close the connection before the connection is actually
	// established, any queued messages will be discarded immediately.
	// (We will not attempt to flush the queue and confirm delivery to the
	// remote host, which ordinarily happens when a connection is closed.)
	ConnectionStateConnecting ConnectionState = C.k_ESteamNetworkingConnectionState_Connecting

	// Some connection types use a back channel or trusted 3rd party
	// for earliest communication.  If the server accepts the connection,
	// then these connections switch into the rendezvous state.  During this
	// state, we still have not yet established an end-to-end route (through
	// the relay network), and so if you send any messages unreliable, they
	// are going to be discarded.
	ConnectionStateFindingRoute ConnectionState = C.k_ESteamNetworkingConnectionState_FindingRoute

	// We've received communications from our peer (and we know
	// who they are) and are all good.  If you close the connection now,
	// we will make our best effort to flush out any reliable sent data that
	// has not been acknowledged by the peer.  (But note that this happens
	// from within the application process, so unlike a TCP connection, you are
	// not totally handing it off to the operating system to deal with it.)
	ConnectionStateConnected ConnectionState = C.k_ESteamNetworkingConnectionState_Connected

	// Connection has been closed by our peer, but not closed locally.
	// The connection still exists from an API perspective.  You must close the
	// handle to free up resources.  If there are any messages in the inbound queue,
	// you may retrieve them.  Otherwise, nothing may be done with the connection
	// except to close it.
	//
	// This stats is similar to CLOSE_WAIT in the TCP state machine.
	ConnectionStateClosedByPeer ConnectionState = C.k_ESteamNetworkingConnectionState_ClosedByPeer

	// A disruption in the connection has been detected locally.  (E.g. timeout,
	// local internet connection disrupted, etc.)
	//
	// The connection still exists from an API perspective.  You must close the
	// handle to free up resources.
	//
	// Attempts to send further messages will fail.  Any remaining received messages
	// in the queue are available.
	ConnectionStateProblemDetectedLocally ConnectionState = C.k_ESteamNetworkingConnectionState_ProblemDetectedLocally
)

// ConnectionEndReason is the interface to ESteamNetConnectionEnd
//
// Enumerate various causes of connection termination.  These are designed to work similar
// to HTTP error codes: the numeric range gives you a rough classification as to the source
// of the problem.
type ConnectionEndReason C.ESteamNetConnectionEnd

// ConnectionEndReason constants
const (
	// Invalid/sentinel value
	ConnectionEndInvalid ConnectionEndReason = C.k_ESteamNetConnectionEnd_Invalid

	//
	// Application codes.  These are the values you will pass to
	// ISteamNetworkingSockets::CloseConnection.  You can use these codes if
	// you want to plumb through application-specific reason codes.  If you don't
	// need this facility, feel free to always pass
	// k_ESteamNetConnectionEnd_App_Generic.
	//
	// The distinction between "normal" and "exceptional" termination is
	// one you may use if you find useful, but it's not necessary for you
	// to do so.  The only place where we distinguish between normal and
	// exceptional is in connection analytics.  If a significant
	// proportion of connections terminates in an exceptional manner,
	// this can trigger an alert.
	//

	// 1xxx: Application ended the connection in a "usual" manner.
	//       E.g.: user intentionally disconnected from the server,
	//             gameplay ended normally, etc
	ConnectionEndAppMin     ConnectionEndReason = C.k_ESteamNetConnectionEnd_App_Min
	ConnectionEndAppGeneric ConnectionEndReason = C.k_ESteamNetConnectionEnd_App_Generic
	// Use codes in this range for "normal" disconnection
	ConnectionEndAppMax ConnectionEndReason = C.k_ESteamNetConnectionEnd_App_Max

	// 2xxx: Application ended the connection in some sort of exceptional
	//       or unusual manner that might indicate a bug or configuration
	//       issue.
	//
	ConnectionEndAppExceptionMin     ConnectionEndReason = C.k_ESteamNetConnectionEnd_AppException_Min
	ConnectionEndAppExceptionGeneric ConnectionEndReason = C.k_ESteamNetConnectionEnd_AppException_Generic
	// Use codes in this range for "unusual" disconnection
	ConnectionEndAppExceptionMax ConnectionEndReason = C.k_ESteamNetConnectionEnd_AppException_Max

	//
	// System codes.  These will be returned by the system when
	// the connection state is k_ESteamNetworkingConnectionState_ClosedByPeer
	// or k_ESteamNetworkingConnectionState_ProblemDetectedLocally.  It is
	// illegal to pass a code in this range to ISteamNetworkingSockets::CloseConnection
	//

	// 3xxx: Connection failed or ended because of problem with the
	//       local host or their connection to the Internet.
	ConnectionEndLocalMin ConnectionEndReason = C.k_ESteamNetConnectionEnd_Local_Min

	// You cannot do what you want to do because you're running in offline mode.
	ConnectionEndLocalOfflineMode ConnectionEndReason = C.k_ESteamNetConnectionEnd_Local_OfflineMode

	// We're having trouble contacting many (perhaps all) relays.
	// Since it's unlikely that they all went offline at once, the best
	// explanation is that we have a problem on our end.  Note that we don't
	// bother distinguishing between "many" and "all", because in practice,
	// it takes time to detect a connection problem, and by the time
	// the connection has timed out, we might not have been able to
	// actively probe all of the relay clusters, even if we were able to
	// contact them at one time.  So this code just means that:
	//
	// * We don't have any recent successful communication with any relay.
	// * We have evidence of recent failures to communicate with multiple relays.
	ConnectionEndLocalManyRelayConnectivity ConnectionEndReason = C.k_ESteamNetConnectionEnd_Local_ManyRelayConnectivity

	// A hosted server is having trouble talking to the relay
	// that the client was using, so the problem is most likely
	// on our end
	ConnectionEndLocalHostedServerPrimaryRelay ConnectionEndReason = C.k_ESteamNetConnectionEnd_Local_HostedServerPrimaryRelay

	// We're not able to get the network config.  This is
	// *almost* always a local issue, since the network config
	// comes from the CDN, which is pretty darn reliable.
	ConnectionEndLocalNetworkConfig ConnectionEndReason = C.k_ESteamNetConnectionEnd_Local_NetworkConfig

	// Steam rejected our request because we don't have rights
	// to do this.
	ConnectionEndLocalRights ConnectionEndReason = C.k_ESteamNetConnectionEnd_Local_Rights

	ConnectionEndLocalMax ConnectionEndReason = C.k_ESteamNetConnectionEnd_Local_Max

	// 4xxx: Connection failed or ended, and it appears that the
	//       cause does NOT have to do with the local host or their
	//       connection to the Internet.  It could be caused by the
	//       remote host, or it could be somewhere in between.
	ConnectionEndRemoteMin ConnectionEndReason = C.k_ESteamNetConnectionEnd_Remote_Min

	// The connection was lost, and as far as we can tell our connection
	// to relevant services (relays) has not been disrupted.  This doesn't
	// mean that the problem is "their fault", it just means that it doesn't
	// appear that we are having network issues on our end.
	ConnectionEndRemoteTimeout ConnectionEndReason = C.k_ESteamNetConnectionEnd_Remote_Timeout

	// Something was invalid with the cert or crypt handshake
	// info you gave me, I don't understand or like your key types,
	// etc.
	ConnectionEndRemoteBadCrypt ConnectionEndReason = C.k_ESteamNetConnectionEnd_Remote_BadCrypt

	// You presented me with a cert that was I was able to parse
	// and *technically* we could use encrypted communication.
	// But there was a problem that prevents me from checking your identity
	// or ensuring that somebody int he middle can't observe our communication.
	// E.g.: - the CA key was missing (and I don't accept unsigned certs)
	// - The CA key isn't one that I trust,
	// - The cert doesn't was appropriately restricted by app, user, time, data center, etc.
	// - The cert wasn't issued to you.
	// - etc
	ConnectionEndRemoteBadCert ConnectionEndReason = C.k_ESteamNetConnectionEnd_Remote_BadCert

	// We couldn't rendezvous with the remote host because
	// they aren't logged into Steam
	ConnectionEndRemoteNotLoggedIn ConnectionEndReason = C.k_ESteamNetConnectionEnd_Remote_NotLoggedIn

	// We couldn't rendezvous with the remote host because
	// they aren't running the right application.
	ConnectionEndRemoteNotRunningApp ConnectionEndReason = C.k_ESteamNetConnectionEnd_Remote_NotRunningApp

	// Something wrong with the protocol version you are using.
	// (Probably the code you are running is too old.)
	ConnectionEndRemoteBadProtocolVersion ConnectionEndReason = C.k_ESteamNetConnectionEnd_Remote_BadProtocolVersion

	ConnectionEndRemoteMax ConnectionEndReason = C.k_ESteamNetConnectionEnd_Remote_Max

	// 5xxx: Connection failed for some other reason.
	ConnectionEndMiscMin ConnectionEndReason = C.k_ESteamNetConnectionEnd_Misc_Min

	// A failure that isn't necessarily the result of a software bug,
	// but that should happen rarely enough that it isn't worth specifically
	// writing UI or making a localized message for.
	// The debug string should contain further details.
	ConnectionEndMiscGeneric ConnectionEndReason = C.k_ESteamNetConnectionEnd_Misc_Generic

	// Generic failure that is most likely a software bug.
	ConnectionEndMiscInternalError ConnectionEndReason = C.k_ESteamNetConnectionEnd_Misc_InternalError

	// The connection to the remote host timed out, but we
	// don't know if the problem is on our end, in the middle,
	// or on their end.
	ConnectionEndMiscTimeout ConnectionEndReason = C.k_ESteamNetConnectionEnd_Misc_Timeout

	// We're having trouble talking to the relevant relay.
	// We don't have enough information to say whether the
	// problem is on our end or not.
	ConnectionEndMiscRelayConnectivity ConnectionEndReason = C.k_ESteamNetConnectionEnd_Misc_RelayConnectivity

	// There's some trouble talking to Steam.
	ConnectionEndMiscSteamConnectivity ConnectionEndReason = C.k_ESteamNetConnectionEnd_Misc_SteamConnectivity

	// A server in a dedicated hosting situation has no relay sessions
	// active with which to talk back to a client.  (It's the client's
	// job to open and maintain those sessions.)
	ConnectionEndMiscNoRelaySessionsToClient ConnectionEndReason = C.k_ESteamNetConnectionEnd_Misc_NoRelaySessionsToClient
	ConnectionEndMiscMax                     ConnectionEndReason = C.k_ESteamNetConnectionEnd_Misc_Max
)

// ConnectionInfo is the interface to SteamNetConnectionInfo_t
//
// Describe the state of a connection.
type ConnectionInfo = C.SteamNetConnectionInfo_t

// RemoteIdentity returns m_identityRemote
//
// Who is on the other end?  Depending on the connection type and phase of the connection, we might not know
func (info *ConnectionInfo) RemoteIdentity() *Identity { return &info.m_identityRemote }

// UserData returns m_nUserData
//
// Arbitrary user data set by the local application code
func (info *ConnectionInfo) UserData() int64 { return (int64)(info.m_nUserData) }

// ListenSocket returns m_hListenSocket
//
/// Handle to listen socket this was connected on, or k_HSteamListenSocket_Invalid if we initiated the connection
func (info *ConnectionInfo) ListenSocket() ListenSocket { return (ListenSocket)(info.m_hListenSocket) }

// RemoteAddr returns m_addrRemote
//
// Remote address.  Might be all 0's if we don't know it, or if this is N/A.
// (E.g. Basically everything except direct UDP connection.)
func (info *ConnectionInfo) RemoteAddr() *IPAddr { return &info.m_addrRemote }

// State returns m_eState
//
// High level state of the connection
func (info *ConnectionInfo) State() ConnectionState { return (ConnectionState)(info.m_eState) }

// EndReason returns m_eEndReason
//
// Basic cause of the connection termination or problem.
func (info *ConnectionInfo) EndReason() ConnectionEndReason {
	return (ConnectionEndReason)(info.m_eEndReason)
}

// EndDebug returns m_szEndDebug
//
// Human-readable, but non-localized explanation for connection
// termination or problem.  This is intended for debugging /
// diagnostic purposes only, not to display to users.  It might
// have some details specific to the issue.
func (info *ConnectionInfo) EndDebug() string {
	return C.GoString(&info.m_szEndDebug[0])
}

// Description returns m_szConnectionDescription
//
// Debug description.  This includes the connection handle,
// connection type (and peer information), and the app name.
// This string is used in various internal logging messages
func (info *ConnectionInfo) Description() string {
	return C.GoString(&info.m_szConnectionDescription[0])
}

type quickConnectionStatus = C.SteamNetworkingQuickConnectionStatus

func (s *quickConnectionStatus) unpack() *QuickConnectionStatus {
	return &QuickConnectionStatus{
		State:                   (ConnectionState)(s.m_eState),
		Ping:                    (int)(s.m_nPing),
		ConnectionQualityLocal:  (float32)(s.m_flConnectionQualityLocal),
		ConnectionQualityRemote: (float32)(s.m_flConnectionQualityRemote),
		OutPacketsPerSec:        (float32)(s.m_flOutPacketsPerSec),
		OutBytesPerSec:          (float32)(s.m_flOutBytesPerSec),
		InPacketsPerSec:         (float32)(s.m_flInPacketsPerSec),
		InBytesPerSec:           (float32)(s.m_flInBytesPerSec),
		SendRateBytesPerSecond:  (int)(s.m_nSendRateBytesPerSecond),
		PendingUnreliable:       (int)(s.m_cbPendingUnreliable),
		PendingReliable:         (int)(s.m_cbPendingReliable),
		SentUnackedReliable:     (int)(s.m_cbSentUnackedReliable),
		QueueTime:               (time.Duration)(s.m_usecQueueTime) * time.Microsecond,
	}
}

// QuickConnectionStatus is the interface to SteamNetworkingQuickConnectionStatus
//
// Quick connection state, pared down to something you could call
// more frequently without it being too big of a perf hit.
type QuickConnectionStatus struct {
	/// High level state of the connection
	State ConnectionState

	/// Current ping (ms)
	Ping int

	/// Connection quality measured locally, 0...1.  (Percentage of packets delivered
	/// end-to-end in order).
	ConnectionQualityLocal float32

	/// Packet delivery success rate as observed from remote host
	ConnectionQualityRemote float32

	/// Current data rates from recent history.
	OutPacketsPerSec float32
	OutBytesPerSec   float32
	InPacketsPerSec  float32
	InBytesPerSec    float32

	/// Estimate rate that we believe that we can send data to our peer.
	/// Note that this could be significantly higher than m_flOutBytesPerSec,
	/// meaning the capacity of the channel is higher than you are sending data.
	/// (That's OK!)
	SendRateBytesPerSecond int

	/// Number of bytes pending to be sent.  This is data that you have recently
	/// requested to be sent but has not yet actually been put on the wire.  The
	/// reliable number ALSO includes data that was previously placed on the wire,
	/// but has now been scheduled for re-transmission.  Thus, it's possible to
	/// observe m_cbPendingReliable increasing between two checks, even if no
	/// calls were made to send reliable data between the checks.  Data that is
	/// awaiting the Nagle delay will appear in these numbers.
	PendingUnreliable int
	PendingReliable   int

	/// Number of bytes of reliable data that has been placed the wire, but
	/// for which we have not yet received an acknowledgment, and thus we may
	/// have to re-transmit.
	SentUnackedReliable int

	/// If you asked us to send a message right now, how long would that message
	/// sit in the queue before we actually started putting packets on the wire?
	/// (And assuming Nagle does not cause any packets to be delayed.)
	///
	/// In general, data that is sent by the application is limited by the
	/// bandwidth of the channel.  If you send data faster than this, it must
	/// be queued and put on the wire at a metered rate.  Even sending a small amount
	/// of data (e.g. a few MTU, say ~3k) will require some of the data to be delayed
	/// a bit.
	///
	/// In general, the estimated delay will be approximately equal to
	///
	///		( m_cbPendingUnreliable+m_cbPendingReliable ) / m_nSendRateBytesPerSecond
	///
	/// plus or minus one MTU.  It depends on how much time has elapsed since the last
	/// packet was put on the wire.  For example, the queue might have *just* been emptied,
	/// and the last packet placed on the wire, and we are exactly up against the send
	/// rate limit.  In that case we might need to wait for one packet's worth of time to
	/// elapse before we can send again.  On the other extreme, the queue might have data
	/// in it waiting for Nagle.  (This will always be less than one packet, because as soon
	/// as we have a complete packet we would send it.)  In that case, we might be ready
	/// to send data now, and this value will be 0.
	QueueTime time.Duration
}

// static library variables, set using Init()
var globsock unsafe.Pointer
var globutil unsafe.Pointer

// InitLibrary is the interface to GameNetworkingSockets_Init
//
// Initialize the library.  Optionally, you can set an initial identity for the default
// interface that is returned by SteamNetworkingSockets().
//
// On failure, false is returned, and a non-localized diagnostic message is returned.
func InitLibrary(id *Identity) error {
	if globsock != nil && globutil != nil {
		return nil
	}

	var err C.SteamNetworkingErrMsg
	if C.GameNetworkingSockets_Init(id, &err) {
		globsock = unsafe.Pointer(C.SteamAPI_SteamNetworkingSockets_v008())
		globutil = unsafe.Pointer(C.SteamAPI_SteamNetworkingUtils_v003())
		if globsock == nil || globutil == nil {
			return errors.New("gns: API initialization error")
		}

		return nil
	}
	return errors.New("gns: " + C.GoString(&err[0]))
}

// KillLibrary is the interface to GameNetworkingSockets_Kill
//
// Close all connections and listen sockets and free all resources.
func KillLibrary() {
	C.GameNetworkingSockets_Kill()
	SetDebugOutputFunction(DebugOutputTypeNone, nil)
	globsock = nil
	globutil = nil
}

// SetDebugOutputFunction is the interface to ISteamNetworkingUtils::SetDebugOutputFunction
//
// Set a function to receive network-related information that is useful for debugging.
// This can be very useful during development, but it can also be useful for troubleshooting
// problems with tech savvy end users.  If you have a console or other log that customers
// can examine, these log messages can often be helpful to troubleshoot network issues.
// (Especially any warning/error messages.)
//
// The detail level indicates what message to invoke your callback on.  Lower numeric
// value means more important, and the value you pass is the lowest priority (highest
// numeric value) you wish to receive callbacks for.
//
// Except when debugging, you should only use k_ESteamNetworkingSocketsDebugOutputType_Msg
// or k_ESteamNetworkingSocketsDebugOutputType_Warning.  For best performance, do NOT
// request a high detail level and then filter out messages in your callback.  This incurs
// all of the expense of formatting the messages, which are then discarded.  Setting a high
// priority value (low numeric value) here allows the library to avoid doing this work.
//
// IMPORTANT: This may be called from a service thread, while we own a mutex, etc.
// Your output function must be threadsafe and fast!  Do not make any other
// Steamworks calls from within the handler.
func SetDebugOutputFunction(eDetailLevel DebugOutputType, logFun DebugOutputFunc) {
	debugOutputCallback = logFun
	if logFun != nil {
		lvl := (C.ESteamNetworkingSocketsDebugOutputType)(eDetailLevel)
		fun := (C.FSteamNetworkingSocketsDebugOutput)(C.goDebugOutputCallback)
		C.SteamAPI_ISteamNetworkingUtils_SetDebugOutputFunction(globutil, lvl, fun)
	} else {
		C.SteamAPI_ISteamNetworkingUtils_SetDebugOutputFunction(globutil, C.k_ESteamNetworkingSocketsDebugOutputType_None, nil)
	}
}

var statusChangedCallback uint32

// RunCallbacks is the interface to ISteamNetworkingSockets::RunCallbacks
//
// Invoke all callbacks queued for this interface.
// On Steam, callbacks are dispatched via the ordinary Steamworks callbacks mechanism.
// So if you have code that is also targeting Steam, you should call this at about the
// same time you would call SteamAPI_RunCallbacks and SteamGameServer_RunCallbacks.
func RunCallbacks(callback StatusChangedCallback) {
	idx := atomic.AddUint32(&statusChangedCallback, 1) % uint32(len(statusChangedCallbacks))
	if statusChangedCallbacks[idx] != nil {
		panic("gns: Too many pending StatusChangedCallbacks")
	}

	statusChangedCallbacks[idx] = callback
	C.SteamAPI_ISteamNetworkingSockets_RunConnectionStatusChangedCallbacks((C.intptr_t)((uintptr)(globsock)), (C.FSteamNetConnectionStatusChangedCallback)(C.goStatusChangedCallback), (C.intptr_t)(idx))
	statusChangedCallbacks[idx] = nil
}

func setConfigValue(opt ConfigOption, val interface{}, eScopeType C.ESteamNetworkingConfigScope, scopeObj C.intptr_t) bool {
	cfg := NewConfigValue(opt, val)
	res := C.SteamAPI_ISteamNetworkingUtils_SetConfigValueStruct(globutil, cfg, eScopeType, scopeObj)
	return (bool)(res)
}

func getConfigValue(opt ConfigOption, eScopeType C.ESteamNetworkingConfigScope, scopeObj C.intptr_t) interface{} {
	var cfg ConfigValue
	val := (C.ESteamNetworkingConfigValue)(opt)
	len := (C.size_t)(len(cfg.m_val))

	if C.SteamAPI_ISteamNetworkingUtils_GetConfigValue(globutil, val, eScopeType, scopeObj, &cfg.m_eDataType, unsafe.Pointer(&cfg.m_val), &len) == 1 {
		return cfg.Val()
	}

	return nil
}

// SetGlobalConfigValue for global scope
func SetGlobalConfigValue(opt ConfigOption, val interface{}) bool {
	return setConfigValue(opt, val, C.k_ESteamNetworkingConfig_Global, 0)
}

// GetGlobalConfigValue for global scope
func GetGlobalConfigValue(opt ConfigOption) interface{} {
	return getConfigValue(opt, C.k_ESteamNetworkingConfig_Global, 0)
}

// SetInterfaceConfigValue for interface scope
func SetInterfaceConfigValue(opt ConfigOption, val interface{}) bool {
	return setConfigValue(opt, val, C.k_ESteamNetworkingConfig_SocketsInterface, (C.intptr_t)((uintptr)(globsock)))
}

// GetInterfaceConfigValue for interface scope
func GetInterfaceConfigValue(opt ConfigOption) interface{} {
	return getConfigValue(opt, C.k_ESteamNetworkingConfig_SocketsInterface, (C.intptr_t)((uintptr)(globsock)))
}

// GetIdentity is the interface to ISteamNetworkingSockets::GetIdentity
//
// Get the identity assigned to this interface.
// E.g. on Steam, this is the user's SteamID, or for the gameserver interface, the SteamID assigned
// to the gameserver.  Returns false and sets the result to an invalid identity if we don't know
// our identity yet.  (E.g. GameServer has not logged in.  On Steam, the user will know their SteamID
// even if they are not signed into Steam.)
func GetIdentity(buf *Identity) bool {
	res := C.SteamAPI_ISteamNetworkingSockets_GetIdentity(globsock, buf)
	return (bool)(res)
}

// LocalIdentity is a GetIdentity convencience wrapper
func LocalIdentity() *Identity {
	var buf Identity
	if GetIdentity(&buf) {
		return &buf
	}
	return nil
}

// LocalTimestamp is the interface to ISteamNetworkingUtils::GetLocalTimestamp
//
// Fetch current timestamp.  This timer has the following properties:
//
//  - Monotonicity is guaranteed.
//  - The initial value will be at least 24*3600*30*1e6, i.e. about
//    30 days worth of microseconds.  In this way, the timestamp value of
//    0 will always be at least "30 days ago".  Also, negative numbers
//    will never be returned.
//  - Wraparound / overflow is not a practical concern.
//
// If you are running under the debugger and stop the process, the clock
// might not advance the full wall clock time that has elapsed between
// calls.  If the process is not blocked from normal operation, the
// timestamp values will track wall clock time, even if you don't call
// the function frequently.
//
// The value is only meaningful for this run of the process.  Don't compare
// it to values obtained on another computer, or other runs of the same process.
func LocalTimestamp() Timestamp {
	res := C.SteamAPI_ISteamNetworkingUtils_GetLocalTimestamp(globutil)
	return (Timestamp)(res)
}

// CreateListenSocketIP is the interface to ISteamNetworkingSockets::CreateListenSocketIP
//
// Creates a "server" socket that listens for clients to connect to by
// calling ConnectByIPAddress, over ordinary UDP (IPv4 or IPv6)
//
// You must select a specific local port to listen on and set it
// the port field of the local address.
//
// Usually you will set the IP portion of the address to zero (SteamNetworkingIPAddr::Clear()).
// This means that you will not bind to any particular local interface (i.e. the same
// as INADDR_ANY in plain socket code).  Furthermore, if possible the socket will be bound
// in "dual stack" mode, which means that it can accept both IPv4 and IPv6 client connections.
// If you really do wish to bind a particular interface, then set the local address to the
// appropriate IPv4 or IPv6 IP.
//
// If you need to set any initial config options, pass them here.  See
// SteamNetworkingConfigValue_t for more about why this is preferable to
// setting the options "immediately" after creation.
//
// When a client attempts to connect, a SteamNetConnectionStatusChangedCallback_t
// will be posted.  The connection will be in the connecting state.
func CreateListenSocketIP(localAddress *IPAddr, config ConfigMap) ListenSocket {
	cfg := config.pack()
	ptr := (*C.SteamNetworkingConfigValue_t)(nil)
	if len(cfg) > 0 {
		ptr = &cfg[0]
	}
	res := C.SteamAPI_ISteamNetworkingSockets_CreateListenSocketIP(globsock, localAddress, (C.int)(len(cfg)), ptr)
	return (ListenSocket)(res)
}

// Close is the interface to ISteamNetworkingSockets::CloseListenSocket
//
// Destroy a listen socket.  All the connections that were accepting on the listen
// socket are closed ungracefully.
func (sock ListenSocket) Close() bool {
	res := C.SteamAPI_ISteamNetworkingSockets_CloseListenSocket(globsock, (C.HSteamListenSocket)(sock))
	return (bool)(res)
}

// SetConfigValue for ListenSocket scope
func (sock ListenSocket) SetConfigValue(opt ConfigOption, val interface{}) bool {
	return setConfigValue(opt, val, C.k_ESteamNetworkingConfig_ListenSocket, (C.intptr_t)(sock))
}

// GetConfigValue for ListenSocket scope
func (sock ListenSocket) GetConfigValue(opt ConfigOption) interface{} {
	return getConfigValue(opt, C.k_ESteamNetworkingConfig_ListenSocket, (C.intptr_t)(sock))
}

// GetListenAddr is the interface to ISteamNetworkingSockets::GetListenSocketAddress
//
// Returns local IP and port that a listen socket created using CreateListenSocketIP is bound to.
//
// An IPv6 address of ::0 means "any IPv4 or IPv6"
// An IPv6 address of ::ffff:0000:0000 means "any IPv4"
func (sock ListenSocket) GetListenAddr(buf *IPAddr) bool {
	res := C.SteamAPI_ISteamNetworkingSockets_GetListenSocketAddress(globsock, (C.HSteamListenSocket)(sock), buf)
	return (bool)(res)
}

// ListenAddr is a GetAddress convencience wrapper
func (sock ListenSocket) ListenAddr() *IPAddr {
	var buf IPAddr
	if sock.GetListenAddr(&buf) {
		return &buf
	}
	return nil
}

// ConnectByIPAddress is the interface to ISteamNetworkingSockets::ConnectByIPAddress
//
// Creates a connection and begins talking to a "server" over UDP at the
// given IPv4 or IPv6 address.  The remote host must be listening with a
// matching call to CreateListenSocketIP on the specified port.
//
// A SteamNetConnectionStatusChangedCallback_t callback will be triggered when we start
// connecting, and then another one on either timeout or successful connection.
//
// If the server does not have any identity configured, then their network address
// will be the only identity in use.  Or, the network host may provide a platform-specific
// identity with or without a valid certificate to authenticate that identity.  (These
// details will be contained in the SteamNetConnectionStatusChangedCallback_t.)  It's
// up to your application to decide whether to allow the connection.
//
// By default, all connections will get basic encryption sufficient to prevent
// casual eavesdropping.  But note that without certificates (or a shared secret
// distributed through some other out-of-band mechanism), you don't have any
// way of knowing who is actually on the other end, and thus are vulnerable to
// man-in-the-middle attacks.
//
// If you need to set any initial config options, pass them here.  See
// SteamNetworkingConfigValue_t for more about why this is preferable to
// setting the options "immediately" after creation.
func ConnectByIPAddress(address *IPAddr, config ConfigMap) Connection {
	cfg := config.pack()
	ptr := (*C.SteamNetworkingConfigValue_t)(nil)
	if len(cfg) > 0 {
		ptr = &cfg[0]
	}
	res := C.SteamAPI_ISteamNetworkingSockets_ConnectByIPAddress(globsock, address, (C.int)(len(cfg)), ptr)
	return (Connection)(res)
}

// CreateSocketPair is the interface to ISteamNetworkingSockets::CreateSocketPair
//
// Create a pair of connections that are talking to each other, e.g. a loopback connection.
// This is very useful for testing, or so that your client/server code can work the same
// even when you are running a local "server".
//
// The two connections will immediately be placed into the connected state, and no callbacks
// will be posted immediately.  After this, if you close either connection, the other connection
// will receive a callback, exactly as if they were communicating over the network.  You must
// close *both* sides in order to fully clean up the resources!
//
// By default, internal buffers are used, completely bypassing the network, the chopping up of
// messages into packets, encryption, copying the payload, etc.  This means that loopback
// packets, by default, will not simulate lag or loss.  Passing true for bUseNetworkLoopback will
// cause the socket pair to send packets through the local network loopback device (127.0.0.1)
// on ephemeral ports.  Fake lag and loss are supported in this case, and CPU time is expended
// to encrypt and decrypt.
//
// If you wish to assign a specific identity to either connection, you may pass a particular
// identity.  Otherwise, if you pass nullptr, the respective connection will assume a generic
// "localhost" identity.  If you use real network loopback, this might be translated to the
// actual bound loopback port.  Otherwise, the port will be zero.
func CreateSocketPair(bUseNetworkLoopback bool, pIdentity1 *Identity, pIdentity2 *Identity) (Connection, Connection) {
	var conn1 C.HSteamNetConnection
	var conn2 C.HSteamNetConnection
	C.SteamAPI_ISteamNetworkingSockets_CreateSocketPair(globsock, &conn1, &conn2, (C.bool)(bUseNetworkLoopback), pIdentity1, pIdentity2)
	return (Connection)(conn1), (Connection)(conn2)
}

// SendMessages is the interface to ISteamNetworkingSockets::SendMessages
//
// Send one or more messages without copying the message payload.
// This is the most efficient way to send messages. To use this
// function, you must first allocate a message object using
// ISteamNetworkingUtils::AllocateMessage.  (Do not declare one
// on the stack or allocate your own.)
//
// You should fill in the message payload.  You can either let
// it allocate the buffer for you and then fill in the payload,
// or if you already have a buffer allocated, you can just point
// m_pData at your buffer and set the callback to the appropriate function
// to free it.  Note that if you use your own buffer, it MUST remain valid
// until the callback is executed.  And also note that your callback can be
// invoked at ant time from any thread (perhaps even before SendMessages
// returns!), so it MUST be fast and threadsafe.
//
// You MUST also fill in:
//  - m_conn - the handle of the connection to send the message to
//  - m_nFlags - bitmask of k_nSteamNetworkingSend_xxx flags.
//
// All other fields are currently reserved and should not be modified.
//
// The library will take ownership of the message structures.  They may
// be modified or become invalid at any time, so you must not read them
// after passing them to this function.
//
// pOutMessageNumberOrResult is an optional array that will receive,
// for each message, the message number that was assigned to the message
// if sending was successful.  If sending failed, then a negative EResult
// value is placed into the array.  For example, the array will hold
// -k_EResultInvalidState if the connection was in an invalid state.
// See ISteamNetworkingSockets::SendMessageToConnection for possible
// failure codes.
func SendMessages(messages []*Message) []int64 {
	if len(messages) == 0 {
		return nil
	}

	res := make([]int64, len(messages))
	C.SteamAPI_ISteamNetworkingSockets_SendMessages(globsock, (C.int)(len(messages)), &messages[0], (*C.int64_t)(&res[0]))
	return res
}

// Accept is the interface to ISteamNetworkingSockets::AcceptConnection
//
// Accept an incoming connection that has been received on a listen socket.
//
// When a connection attempt is received (perhaps after a few basic handshake
// packets have been exchanged to prevent trivial spoofing), a connection interface
// object is created in the k_ESteamNetworkingConnectionState_Connecting state
// and a SteamNetConnectionStatusChangedCallback_t is posted.  At this point, your
// application MUST either accept or close the connection.  (It may not ignore it.)
// Accepting the connection will transition it either into the connected state,
// or the finding route state, depending on the connection type.
//
// You should take action within a second or two, because accepting the connection is
// what actually sends the reply notifying the client that they are connected.  If you
// delay taking action, from the client's perspective it is the same as the network
// being unresponsive, and the client may timeout the connection attempt.  In other
// words, the client cannot distinguish between a delay caused by network problems
// and a delay caused by the application.
//
// This means that if your application goes for more than a few seconds without
// processing callbacks (for example, while loading a map), then there is a chance
// that a client may attempt to connect in that interval and fail due to timeout.
//
// If the application does not respond to the connection attempt in a timely manner,
// and we stop receiving communication from the client, the connection attempt will
// be timed out locally, transitioning the connection to the
// k_ESteamNetworkingConnectionState_ProblemDetectedLocally state.  The client may also
// close the connection before it is accepted, and a transition to the
// k_ESteamNetworkingConnectionState_ClosedByPeer is also possible depending the exact
// sequence of events.
//
// Returns k_EResultInvalidParam if the handle is invalid.
// Returns k_EResultInvalidState if the connection is not in the appropriate state.
// (Remember that the connection state could change in between the time that the
// notification being posted to the queue and when it is received by the application.)
//
// A note about connection configuration options.  If you need to set any configuration
// options that are common to all connections accepted through a particular listen
// socket, consider setting the options on the listen socket, since such options are
// inherited automatically.  If you really do need to set options that are connection
// specific, it is safe to set them on the connection before accepting the connection.
func (conn Connection) Accept() Result {
	res := C.SteamAPI_ISteamNetworkingSockets_AcceptConnection(globsock, (C.HSteamNetConnection)(conn))
	return (Result)(res)
}

// Close is the interface to ISteamNetworkingSockets::CloseConnection
//
// Disconnects from the remote host and invalidates the connection handle.
// Any unread data on the connection is discarded.
//
// nReason is an application defined code that will be received on the other
// end and recorded (when possible) in backend analytics.  The value should
// come from a restricted range.  (See ESteamNetConnectionEnd.)  If you don't need
// to communicate any information to the remote host, and do not want analytics to
// be able to distinguish "normal" connection terminations from "exceptional" ones,
// You may pass zero, in which case the generic value of
// k_ESteamNetConnectionEnd_App_Generic will be used.
//
// pszDebug is an optional human-readable diagnostic string that will be received
// by the remote host and recorded (when possible) in backend analytics.
//
// If you wish to put the socket into a "linger" state, where an attempt is made to
// flush any remaining sent data, use bEnableLinger=true.  Otherwise reliable data
// is not flushed.
//
// If the connection has already ended and you are just freeing up the
// connection interface, the reason code, debug string, and linger flag are
// ignored.
func (conn Connection) Close(nReason ConnectionEndReason, pszDebug string, bEnableLinger bool) bool {
	var debug *C.char
	if pszDebug != "" {
		debug := C.CString(pszDebug)
		defer C.free(unsafe.Pointer(debug))
	}

	res := C.SteamAPI_ISteamNetworkingSockets_CloseConnection(globsock, (C.HSteamNetConnection)(conn), (C.int)(nReason), debug, (C.bool)(bEnableLinger))
	return (bool)(res)
}

// SetConfigValue for Connection scope
func (conn Connection) SetConfigValue(opt ConfigOption, val interface{}) bool {
	return setConfigValue(opt, val, C.k_ESteamNetworkingConfig_Connection, (C.intptr_t)(conn))
}

// GetConfigValue for Connection scope
func (conn Connection) GetConfigValue(opt ConfigOption) interface{} {
	return getConfigValue(opt, C.k_ESteamNetworkingConfig_Connection, (C.intptr_t)(conn))
}

// SetUserData is the interface to ISteamNetworkingSockets::SetConnectionUserData
//
// Set connection user data.  the data is returned in the following places
//  - You can query it using GetConnectionUserData.
//  - The SteamNetworkingmessage_t structure.
//  - The SteamNetConnectionInfo_t structure.  (Which is a member of SteamNetConnectionStatusChangedCallback_t.)
//
// Returns false if the handle is invalid.
func (conn Connection) SetUserData(nUserData int64) bool {
	res := C.SteamAPI_ISteamNetworkingSockets_SetConnectionUserData(globsock, (C.HSteamNetConnection)(conn), (C.int64_t)(nUserData))
	return (bool)(res)
}

// GetUserData is the interface to ISteamNetworkingSockets::GetConnectionUserData
//
// Fetch connection user data.  Returns -1 if handle is invalid
// or if you haven't set any userdata on the connection.
func (conn Connection) GetUserData() int64 {
	res := C.SteamAPI_ISteamNetworkingSockets_GetConnectionUserData(globsock, (C.HSteamNetConnection)(conn))
	return (int64)(res)
}

// SetName is the interface to ISteamNetworkingSockets::SetConnectionName
//
// Set a name for the connection, used mostly for debugging
func (conn Connection) SetName(pszName string) {
	name := C.CString(pszName)
	defer C.free(unsafe.Pointer(name))

	C.SteamAPI_ISteamNetworkingSockets_SetConnectionName(globsock, (C.HSteamNetConnection)(conn), name)
}

// GetName is the interface to ISteamNetworkingSockets::GetConnectionName
//
// Fetch connection name.  Returns false if handle is invalid
func (conn Connection) GetName() string {
	var buf [2048]C.char
	if !C.SteamAPI_ISteamNetworkingSockets_GetConnectionName(globsock, (C.HSteamNetConnection)(conn), &buf[0], (C.int)(len(buf))) {
		return ""
	}
	return C.GoString(&buf[0])
}

// SendMessage is the interface to ISteamNetworkingSockets::SendMessageToConnection
//
// Send a message to the remote host on the specified connection.
//
// nSendFlags determines the delivery guarantees that will be provided,
// when data should be buffered, etc.  E.g. k_nSteamNetworkingSend_Unreliable
//
// Note that the semantics we use for messages are not precisely
// the same as the semantics of a standard "stream" socket.
// (SOCK_STREAM)  For an ordinary stream socket, the boundaries
// between chunks are not considered relevant, and the sizes of
// the chunks of data written will not necessarily match up to
// the sizes of the chunks that are returned by the reads on
// the other end.  The remote host might read a partial chunk,
// or chunks might be coalesced.  For the message semantics
// used here, however, the sizes WILL match.  Each send call
// will match a successful read call on the remote host
// one-for-one.  If you are porting existing stream-oriented
// code to the semantics of reliable messages, your code should
// work the same, since reliable message semantics are more
// strict than stream semantics.  The only caveat is related to
// performance: there is per-message overhead to retain the
// message sizes, and so if your code sends many small chunks
// of data, performance will suffer. Any code based on stream
// sockets that does not write excessively small chunks will
// work without any changes.
//
// The pOutMessageNumber is an optional pointer to receive the
// message number assigned to the message, if sending was successful.
//
// Returns:
//  - k_EResultInvalidParam: invalid connection handle, or the individual message is too big.
//    (See k_cbMaxSteamNetworkingSocketsMessageSizeSend)
//  - k_EResultInvalidState: connection is in an invalid state
//  - k_EResultNoConnection: connection has ended
//  - k_EResultIgnored: You used k_nSteamNetworkingSend_NoDelay, and the message was dropped because
//    we were not ready to send it.
//  - k_EResultLimitExceeded: there was already too much data queued to be sent.
//    (See k_ESteamNetworkingConfig_SendBufferSize)
func (conn Connection) SendMessage(pData []byte, nSendFlags SendFlags) (int64, Result) {
	var p unsafe.Pointer
	if len(pData) > 0 {
		p = unsafe.Pointer(&pData[0])
	}

	var id C.int64_t
	res := C.SteamAPI_ISteamNetworkingSockets_SendMessageToConnection(globsock, (C.HSteamNetConnection)(conn), p, (C.uint32_t)(len(pData)), (C.int)(nSendFlags), &id)
	return (int64)(id), (Result)(res)
}

// NewMessage is the interface to ISteamNetworkingUtils::AllocateMessage
func (conn Connection) NewMessage(bufSize int, flags SendFlags) *Message {
	msg := C.SteamAPI_ISteamNetworkingUtils_AllocateMessage(globutil, (C.int)(bufSize))
	msg.m_conn = (C.HSteamNetConnection)(conn)
	msg.m_nFlags = (C.int)(flags)
	return msg
}

// Flush is the interface to ISteamNetworkingSockets::FlushMessagesOnConnection
//
// Flush any messages waiting on the Nagle timer and send them
// at the next transmission opportunity (often that means right now).
//
// If Nagle is enabled (it's on by default) then when calling
// SendMessageToConnection the message will be buffered, up to the Nagle time
// before being sent, to merge small messages into the same packet.
// (See k_ESteamNetworkingConfig_NagleTime)
//
// Returns:
// k_EResultInvalidParam: invalid connection handle
// k_EResultInvalidState: connection is in an invalid state
// k_EResultNoConnection: connection has ended
// k_EResultIgnored: We weren't (yet) connected, so this operation has no effect.
func (conn Connection) Flush() Result {
	res := C.SteamAPI_ISteamNetworkingSockets_FlushMessagesOnConnection(globsock, (C.HSteamNetConnection)(conn))
	return (Result)(res)
}

// ReceiveMessages is the interface to ISteamNetworkingSockets::ReceiveMessagesOnConnection
//
// Same as ReceiveMessagesOnConnection, but will return the next messages available
// on any connection in the poll group.  Examine SteamNetworkingMessage_t::m_conn
// to know which connection.  (SteamNetworkingMessage_t::m_nConnUserData might also
// be useful.)
//
// Delivery order of messages among different connections will usually match the
// order that the last packet was received which completed the message.  But this
// is not a strong guarantee, especially for packets received right as a connection
// is being assigned to poll group.
//
// Delivery order of messages on the same connection is well defined and the
// same guarantees are present as mentioned in ReceiveMessagesOnConnection.
// (But the messages are not grouped by connection, so they will not necessarily
// appear consecutively in the list; they may be interleaved with messages for
// other connections.)
func (conn Connection) ReceiveMessages(buf []*Message) int {
	if len(buf) == 0 {
		return 0
	}

	res := C.SteamAPI_ISteamNetworkingSockets_ReceiveMessagesOnConnection(globsock, (C.HSteamNetConnection)(conn), &buf[0], (C.int)(len(buf)))
	return (int)(res)
}

// GetInfo is the interface to ISteamNetworkingSockets::GetConnectionInfo
//
// Returns basic information about the high-level state of the connection.
func (conn Connection) GetInfo(buf *ConnectionInfo) bool {
	res := C.SteamAPI_ISteamNetworkingSockets_GetConnectionInfo(globsock, (C.HSteamNetConnection)(conn), buf)
	return (bool)(res)
}

// Info is a GetInfo convencience wrapper
func (conn Connection) Info() *ConnectionInfo {
	var buf ConnectionInfo
	if conn.GetInfo(&buf) {
		return &buf
	}
	return nil
}

// QuickConnectionStatus is the interface to ISteamNetworkingSockets::GetQuickConnectionStatus
//
// Returns a small set of information about the real-time state of the connection
// Returns false if the connection handle is invalid, or the connection has ended.
func (conn Connection) QuickConnectionStatus() *QuickConnectionStatus {
	var buf quickConnectionStatus
	if C.SteamAPI_ISteamNetworkingSockets_GetQuickConnectionStatus(globsock, (C.HSteamNetConnection)(conn), &buf) {
		return buf.unpack()
	}
	return nil
}

// DetailedConnectionStatus is the interface to ISteamNetworkingSockets::GetDetailedConnectionStatus
//
// Returns detailed connection stats in text format.  Useful
// for dumping to a log, etc.
//
// Returns:
// -1 failure (bad connection handle)
// 0 OK, your buffer was filled in and '\0'-terminated
// >0 Your buffer was either nullptr, or it was too small and the text got truncated.
//    Try again with a buffer of at least N bytes.
func (conn Connection) DetailedConnectionStatus() string {
	var buf [4096]C.char
	res := C.SteamAPI_ISteamNetworkingSockets_GetDetailedConnectionStatus(globsock, (C.HSteamNetConnection)(conn), &buf[0], (C.int)(len(buf)))
	if res < 0 {
		return ""
	} else if res == 0 {
		return C.GoString(&buf[0])
	}

	dynbuf := make([]C.char, res)
	if dynres := C.SteamAPI_ISteamNetworkingSockets_GetDetailedConnectionStatus(globsock, (C.HSteamNetConnection)(conn), &buf[0], res); dynres == 0 {
		return C.GoString(&dynbuf[0])
	}

	return ""
}

// SetPollGroup is the interface to ISteamNetworkingSockets::SetConnectionPollGroup
//
// Assign a connection to a poll group.  Note that a connection may only belong to a
// single poll group.  Adding a connection to a poll group implicitly removes it from
// any other poll group it is in.
//
// You can pass k_HSteamNetPollGroup_Invalid to remove a connection from its current
// poll group without adding it to a new poll group.
//
// If there are received messages currently pending on the connection, an attempt
// is made to add them to the queue of messages for the poll group in approximately
// the order that would have applied if the connection was already part of the poll
// group at the time that the messages were received.
//
// Returns false if the connection handle is invalid, or if the poll group handle
// is invalid (and not k_HSteamNetPollGroup_Invalid).
func (conn Connection) SetPollGroup(hPollGroup PollGroup) bool {
	res := C.SteamAPI_ISteamNetworkingSockets_SetConnectionPollGroup(globsock, (C.HSteamNetConnection)(conn), (C.HSteamNetPollGroup)(hPollGroup))
	return (bool)(res)
}

// NewPollGroup is the interface to ISteamNetworkingSockets::CreatePollGroup
//
// Create a new poll group.
//
// You should destroy the poll group when you are done using DestroyPollGroup
func NewPollGroup() PollGroup {
	res := C.SteamAPI_ISteamNetworkingSockets_CreatePollGroup(globsock)
	return (PollGroup)(res)
}

// Close is the interface to ISteamNetworkingSockets::DestroyPollGroup
//
// Destroy a poll group created with CreatePollGroup().
//
// If there are any connections in the poll group, they are removed from the group,
// and left in a state where they are not part of any poll group.
// Returns false if passed an invalid poll group handle.
func (poll PollGroup) Close() bool {
	res := C.SteamAPI_ISteamNetworkingSockets_DestroyPollGroup(globsock, (C.HSteamNetPollGroup)(poll))
	return (bool)(res)
}

// ReceiveMessages is the interface to ISteamNetworkingSockets::ReceiveMessagesOnPollGroup
//
// Same as ReceiveMessagesOnConnection, but will return the next messages available
// on any connection in the poll group.  Examine SteamNetworkingMessage_t::m_conn
// to know which connection.  (SteamNetworkingMessage_t::m_nConnUserData might also
// be useful.)
//
// Delivery order of messages among different connections will usually match the
// order that the last packet was received which completed the message.  But this
// is not a strong guarantee, especially for packets received right as a connection
// is being assigned to poll group.
//
// Delivery order of messages on the same connection is well defined and the
// same guarantees are present as mentioned in ReceiveMessagesOnConnection.
// (But the messages are not grouped by connection, so they will not necessarily
// appear consecutively in the list; they may be interleaved with messages for
// other connections.)
func (poll PollGroup) ReceiveMessages(buf []*Message) int {
	if len(buf) == 0 {
		return 0
	}

	res := C.SteamAPI_ISteamNetworkingSockets_ReceiveMessagesOnPollGroup(globsock, (C.HSteamNetPollGroup)(poll), &buf[0], (C.int)(len(buf)))
	return (int)(res)
}
