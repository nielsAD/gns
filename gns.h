// Author:  Niels A.D.
// Project: gamenetworkingsockets (https://github.com/nielsAD/gns)
// License: Mozilla Public License, v2.0
//
// C headers for GameNetworkingSockets.
// Imports steamnetworkingsockets_flat.h functions and all inherently required types and constants.

#include <stddef.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>

#if defined(__linux__) || defined(__APPLE__) 
#define PRAGMA_PACK_PUSH _Pragma("pack(push,4)")
#else
#define PRAGMA_PACK_PUSH _Pragma("pack(push,8)")
#endif
#define PRAGMA_PACK_POP _Pragma("pack(pop)")

typedef void ISteamNetworkingSockets;
typedef void ISteamNetworkingUtils;

/// Handle used to identify a "listen socket".  Unlike traditional
/// Berkeley sockets, a listen socket and a connection are two
/// different abstractions.
typedef uint32_t HSteamListenSocket;
enum { k_HSteamListenSocket_Invalid = 0} ;

/// Handle used to identify a connection to a remote host.
typedef uint32_t HSteamNetConnection;
enum { k_HSteamNetConnection_Invalid = 0 };

/// Configuration options
typedef enum ESteamNetworkingConfigValue
{
	k_ESteamNetworkingConfig_Invalid = 0,

	/// [global float, 0--100] Randomly discard N pct of packets instead of sending/recv
	/// This is a global option only, since it is applied at a low level
	/// where we don't have much context
	k_ESteamNetworkingConfig_FakePacketLoss_Send = 2,
	k_ESteamNetworkingConfig_FakePacketLoss_Recv = 3,

	/// [global int32].  Delay all outbound/inbound packets by N ms
	k_ESteamNetworkingConfig_FakePacketLag_Send = 4,
	k_ESteamNetworkingConfig_FakePacketLag_Recv = 5,

	/// [global float] 0-100 Percentage of packets we will add additional delay
	/// to (causing them to be reordered)
	k_ESteamNetworkingConfig_FakePacketReorder_Send = 6,
	k_ESteamNetworkingConfig_FakePacketReorder_Recv = 7,

	/// [global int32] Extra delay, in ms, to apply to reordered packets.
	k_ESteamNetworkingConfig_FakePacketReorder_Time = 8,

	/// [global float 0--100] Globally duplicate some percentage of packets we send
	k_ESteamNetworkingConfig_FakePacketDup_Send = 26,
	k_ESteamNetworkingConfig_FakePacketDup_Recv = 27,

	/// [global int32] Amount of delay, in ms, to delay duplicated packets.
	/// (We chose a random delay between 0 and this value)
	k_ESteamNetworkingConfig_FakePacketDup_TimeMax = 28,

	/// [connection int32] Timeout value (in ms) to use when first connecting
	k_ESteamNetworkingConfig_TimeoutInitial = 24,

	/// [connection int32] Timeout value (in ms) to use after connection is established
	k_ESteamNetworkingConfig_TimeoutConnected = 25,

	/// [connection int32] Upper limit of buffered pending bytes to be sent,
	/// if this is reached SendMessage will return k_EResultLimitExceeded
	/// Default is 512k (524288 bytes)
	k_ESteamNetworkingConfig_SendBufferSize = 9,

	/// [connection int32] Minimum/maximum send rate clamp, 0 is no limit.
	/// This value will control the min/max allowed sending rate that 
	/// bandwidth estimation is allowed to reach.  Default is 0 (no-limit)
	k_ESteamNetworkingConfig_SendRateMin = 10,
	k_ESteamNetworkingConfig_SendRateMax = 11,

	/// [connection int32] Nagle time, in microseconds.  When SendMessage is called, if
	/// the outgoing message is less than the size of the MTU, it will be
	/// queued for a delay equal to the Nagle timer value.  This is to ensure
	/// that if the application sends several small messages rapidly, they are
	/// coalesced into a single packet.
	/// See historical RFC 896.  Value is in microseconds. 
	/// Default is 5000us (5ms).
	k_ESteamNetworkingConfig_NagleTime = 12,

	/// [connection int32] Don't automatically fail IP connections that don't have
	/// strong auth.  On clients, this means we will attempt the connection even if
	/// we don't know our identity or can't get a cert.  On the server, it means that
	/// we won't automatically reject a connection due to a failure to authenticate.
	/// (You can examine the incoming connection and decide whether to accept it.)
	///
	/// This is a dev configuration value, and you should not let users modify it in
	/// production.
	k_ESteamNetworkingConfig_IP_AllowWithoutAuth = 23,

	/// [connection int32] Do not send UDP packets with a payload of
	/// larger than N bytes.  If you set this, k_ESteamNetworkingConfig_MTU_DataSize
	/// is automatically adjusted
	k_ESteamNetworkingConfig_MTU_PacketSize = 32,

	/// [connection int32] (read only) Maximum message size you can send that
	/// will not fragment, based on k_ESteamNetworkingConfig_MTU_PacketSize
	k_ESteamNetworkingConfig_MTU_DataSize = 33,

	/// [connection int32] Allow unencrypted (and unauthenticated) communication.
	/// 0: Not allowed (the default)
	/// 1: Allowed, but prefer encrypted
	/// 2: Allowed, and preferred
	/// 3: Required.  (Fail the connection if the peer requires encryption.)
	///
	/// This is a dev configuration value, since its purpose is to disable encryption.
	/// You should not let users modify it in production.  (But note that it requires
	/// the peer to also modify their value in order for encryption to be disabled.)
	k_ESteamNetworkingConfig_Unencrypted = 34,

	/// [global int32] 0 or 1.  Some variables are "dev" variables.  They are useful
	/// for debugging, but should not be adjusted in production.  When this flag is false (the default),
	/// such variables will not be enumerated by the ISteamnetworkingUtils::GetFirstConfigValue
	/// ISteamNetworkingUtils::GetConfigValueInfo functions.  The idea here is that you
	/// can use those functions to provide a generic mechanism to set any configuration
	/// value from a console or configuration file, looking up the variable by name.  Depending
	/// on your game, modifying other configuration values may also have negative effects, and
	/// you may wish to further lock down which variables are allowed to be modified by the user.
	/// (Maybe no variables!)  Or maybe you use a whitelist or blacklist approach.
	///
	/// (This flag is itself a dev variable.)
	k_ESteamNetworkingConfig_EnumerateDevVars = 35,

	//
	// Settings for SDR relayed connections
	//

	/// [int32 global] If the first N pings to a port all fail, mark that port as unavailable for
	/// a while, and try a different one.  Some ISPs and routers may drop the first
	/// packet, so setting this to 1 may greatly disrupt communications.
	k_ESteamNetworkingConfig_SDRClient_ConsecutitivePingTimeoutsFailInitial = 19,

	/// [int32 global] If N consecutive pings to a port fail, after having received successful 
	/// communication, mark that port as unavailable for a while, and try a 
	/// different one.
	k_ESteamNetworkingConfig_SDRClient_ConsecutitivePingTimeoutsFail = 20,

	/// [int32 global] Minimum number of lifetime pings we need to send, before we think our estimate
	/// is solid.  The first ping to each cluster is very often delayed because of NAT,
	/// routers not having the best route, etc.  Until we've sent a sufficient number
	/// of pings, our estimate is often inaccurate.  Keep pinging until we get this
	/// many pings.
	k_ESteamNetworkingConfig_SDRClient_MinPingsBeforePingAccurate = 21,

	/// [int32 global] Set all steam datagram traffic to originate from the same
	/// local port. By default, we open up a new UDP socket (on a different local
	/// port) for each relay.  This is slightly less optimal, but it works around
	/// some routers that don't implement NAT properly.  If you have intermittent
	/// problems talking to relays that might be NAT related, try toggling
	/// this flag
	k_ESteamNetworkingConfig_SDRClient_SingleSocket = 22,

	/// [global string] Code of relay cluster to force use.  If not empty, we will
	/// only use relays in that cluster.  E.g. 'iad'
	k_ESteamNetworkingConfig_SDRClient_ForceRelayCluster = 29,

	/// [connection string] For debugging, generate our own (unsigned) ticket, using
	/// the specified  gameserver address.  Router must be configured to accept unsigned
	/// tickets.
	k_ESteamNetworkingConfig_SDRClient_DebugTicketAddress = 30,

	/// [global string] For debugging.  Override list of relays from the config with
	/// this set (maybe just one).  Comma-separated list.
	k_ESteamNetworkingConfig_SDRClient_ForceProxyAddr = 31,

	/// [global string] For debugging.  Force ping times to clusters to be the specified
	/// values.  A comma separated list of <cluster>=<ms> values.  E.g. "sto=32,iad=100"
	///
	/// This is a dev configuration value, you probably should not let users modify it
	/// in production.
	k_ESteamNetworkingConfig_SDRClient_FakeClusterPing = 36,

	//
	// Log levels for debuging information.  A higher priority
	// (lower numeric value) will cause more stuff to be printed.  
	//
	k_ESteamNetworkingConfig_LogLevel_AckRTT = 13, // [connection int32] RTT calculations for inline pings and replies
	k_ESteamNetworkingConfig_LogLevel_PacketDecode = 14, // [connection int32] log SNP packets send
	k_ESteamNetworkingConfig_LogLevel_Message = 15, // [connection int32] log each message send/recv
	k_ESteamNetworkingConfig_LogLevel_PacketGaps = 16, // [connection int32] dropped packets
	k_ESteamNetworkingConfig_LogLevel_P2PRendezvous = 17, // [connection int32] P2P rendezvous messages
	k_ESteamNetworkingConfig_LogLevel_SDRRelayPings = 18, // [global int32] Ping relays

	k_ESteamNetworkingConfigValue__Force32Bit = 0x7fffffff
} ESteamNetworkingConfigValue;

// Different configuration values have different data types
typedef enum ESteamNetworkingConfigDataType
{
	k_ESteamNetworkingConfig_Int32 = 1,
	k_ESteamNetworkingConfig_Int64 = 2,
	k_ESteamNetworkingConfig_Float = 3,
	k_ESteamNetworkingConfig_String = 4,
	k_ESteamNetworkingConfig_FunctionPtr = 5, // NOTE: When setting	callbacks, you should put the pointer into a variable and pass a pointer to that variable.

	k_ESteamNetworkingConfigDataType__Force32Bit = 0x7fffffff
} ESteamNetworkingConfigDataType;

/// In a few places we need to set configuration options on listen sockets and connections, and
/// have them take effect *before* the listen socket or connection really starts doing anything.
/// Creating the object and then setting the options "immediately" after creation doesn't work
/// completely, because network packets could be received between the time the object is created and
/// when the options are applied.  To set options at creation time in a reliable way, they must be
/// passed to the creation function.  This structure is used to pass those options.
///
/// For the meaning of these fields, see ISteamNetworkingUtils::SetConfigValue.  Basically
/// when the object is created, we just iterate over the list of options and call
/// ISteamNetworkingUtils::SetConfigValueStruct, where the scope arguments are supplied by the
/// object being created.
typedef struct SteamNetworkingConfigValue_t
{
	/// Which option is being set
	ESteamNetworkingConfigValue m_eValue;

	/// Which field below did you fill in?
	ESteamNetworkingConfigDataType m_eDataType;

	/// Option value
	union
	{
		int32_t m_int32;
		int64_t m_int64;
		float m_float;
		const char *m_string; // Points to your '\0'-terminated buffer
		void *m_functionPtr;
	} m_val;
} SteamNetworkingConfigValue_t;

// General result codes
typedef enum EResult
{
	k_EResultOK	= 1,							// success
	k_EResultFail = 2,							// generic failure 
	k_EResultNoConnection = 3,					// no/failed network connection
//	k_EResultNoConnectionRetry = 4,				// OBSOLETE - removed
	k_EResultInvalidPassword = 5,				// password/ticket is invalid
	k_EResultLoggedInElsewhere = 6,				// same user logged in elsewhere
	k_EResultInvalidProtocolVer = 7,			// protocol version is incorrect
	k_EResultInvalidParam = 8,					// a parameter is incorrect
	k_EResultFileNotFound = 9,					// file was not found
	k_EResultBusy = 10,							// called method busy - action not taken
	k_EResultInvalidState = 11,					// called object was in an invalid state
	k_EResultInvalidName = 12,					// name is invalid
	k_EResultInvalidEmail = 13,					// email is invalid
	k_EResultDuplicateName = 14,				// name is not unique
	k_EResultAccessDenied = 15,					// access is denied
	k_EResultTimeout = 16,						// operation timed out
	k_EResultBanned = 17,						// VAC2 banned
	k_EResultAccountNotFound = 18,				// account not found
	k_EResultInvalidSteamID = 19,				// steamID is invalid
	k_EResultServiceUnavailable = 20,			// The requested service is currently unavailable
	k_EResultNotLoggedOn = 21,					// The user is not logged on
	k_EResultPending = 22,						// Request is pending (may be in process, or waiting on third party)
	k_EResultEncryptionFailure = 23,			// Encryption or Decryption failed
	k_EResultInsufficientPrivilege = 24,		// Insufficient privilege
	k_EResultLimitExceeded = 25,				// Too much of a good thing
	k_EResultRevoked = 26,						// Access has been revoked (used for revoked guest passes)
	k_EResultExpired = 27,						// License/Guest pass the user is trying to access is expired
	k_EResultAlreadyRedeemed = 28,				// Guest pass has already been redeemed by account, cannot be acked again
	k_EResultDuplicateRequest = 29,				// The request is a duplicate and the action has already occurred in the past, ignored this time
	k_EResultAlreadyOwned = 30,					// All the games in this guest pass redemption request are already owned by the user
	k_EResultIPNotFound = 31,					// IP address not found
	k_EResultPersistFailed = 32,				// failed to write change to the data store
	k_EResultLockingFailed = 33,				// failed to acquire access lock for this operation
	k_EResultLogonSessionReplaced = 34,
	k_EResultConnectFailed = 35,
	k_EResultHandshakeFailed = 36,
	k_EResultIOFailure = 37,
	k_EResultRemoteDisconnect = 38,
	k_EResultShoppingCartNotFound = 39,			// failed to find the shopping cart requested
	k_EResultBlocked = 40,						// a user didn't allow it
	k_EResultIgnored = 41,						// target is ignoring sender
	k_EResultNoMatch = 42,						// nothing matching the request found
	k_EResultAccountDisabled = 43,
	k_EResultServiceReadOnly = 44,				// this service is not accepting content changes right now
	k_EResultAccountNotFeatured = 45,			// account doesn't have value, so this feature isn't available
	k_EResultAdministratorOK = 46,				// allowed to take this action, but only because requester is admin
	k_EResultContentVersion = 47,				// A Version mismatch in content transmitted within the Steam protocol.
	k_EResultTryAnotherCM = 48,					// The current CM can't service the user making a request, user should try another.
	k_EResultPasswordRequiredToKickSession = 49,// You are already logged in elsewhere, this cached credential login has failed.
	k_EResultAlreadyLoggedInElsewhere = 50,		// You are already logged in elsewhere, you must wait
	k_EResultSuspended = 51,					// Long running operation (content download) suspended/paused
	k_EResultCancelled = 52,					// Operation canceled (typically by user: content download)
	k_EResultDataCorruption = 53,				// Operation canceled because data is ill formed or unrecoverable
	k_EResultDiskFull = 54,						// Operation canceled - not enough disk space.
	k_EResultRemoteCallFailed = 55,				// an remote call or IPC call failed
	k_EResultPasswordUnset = 56,				// Password could not be verified as it's unset server side
	k_EResultExternalAccountUnlinked = 57,		// External account (PSN, Facebook...) is not linked to a Steam account
	k_EResultPSNTicketInvalid = 58,				// PSN ticket was invalid
	k_EResultExternalAccountAlreadyLinked = 59,	// External account (PSN, Facebook...) is already linked to some other account, must explicitly request to replace/delete the link first
	k_EResultRemoteFileConflict = 60,			// The sync cannot resume due to a conflict between the local and remote files
	k_EResultIllegalPassword = 61,				// The requested new password is not legal
	k_EResultSameAsPreviousValue = 62,			// new value is the same as the old one ( secret question and answer )
	k_EResultAccountLogonDenied = 63,			// account login denied due to 2nd factor authentication failure
	k_EResultCannotUseOldPassword = 64,			// The requested new password is not legal
	k_EResultInvalidLoginAuthCode = 65,			// account login denied due to auth code invalid
	k_EResultAccountLogonDeniedNoMail = 66,		// account login denied due to 2nd factor auth failure - and no mail has been sent
	k_EResultHardwareNotCapableOfIPT = 67,		// 
	k_EResultIPTInitError = 68,					// 
	k_EResultParentalControlRestricted = 69,	// operation failed due to parental control restrictions for current user
	k_EResultFacebookQueryError = 70,			// Facebook query returned an error
	k_EResultExpiredLoginAuthCode = 71,			// account login denied due to auth code expired
	k_EResultIPLoginRestrictionFailed = 72,
	k_EResultAccountLockedDown = 73,
	k_EResultAccountLogonDeniedVerifiedEmailRequired = 74,
	k_EResultNoMatchingURL = 75,
	k_EResultBadResponse = 76,					// parse failure, missing field, etc.
	k_EResultRequirePasswordReEntry = 77,		// The user cannot complete the action until they re-enter their password
	k_EResultValueOutOfRange = 78,				// the value entered is outside the acceptable range
	k_EResultUnexpectedError = 79,				// something happened that we didn't expect to ever happen
	k_EResultDisabled = 80,						// The requested service has been configured to be unavailable
	k_EResultInvalidCEGSubmission = 81,			// The set of files submitted to the CEG server are not valid !
	k_EResultRestrictedDevice = 82,				// The device being used is not allowed to perform this action
	k_EResultRegionLocked = 83,					// The action could not be complete because it is region restricted
	k_EResultRateLimitExceeded = 84,			// Temporary rate limit exceeded, try again later, different from k_EResultLimitExceeded which may be permanent
	k_EResultAccountLoginDeniedNeedTwoFactor = 85,	// Need two-factor code to login
	k_EResultItemDeleted = 86,					// The thing we're trying to access has been deleted
	k_EResultAccountLoginDeniedThrottle = 87,	// login attempt failed, try to throttle response to possible attacker
	k_EResultTwoFactorCodeMismatch = 88,		// two factor code mismatch
	k_EResultTwoFactorActivationCodeMismatch = 89,	// activation code for two-factor didn't match
	k_EResultAccountAssociatedToMultiplePartners = 90,	// account has been associated with multiple partners
	k_EResultNotModified = 91,					// data not modified
	k_EResultNoMobileDevice = 92,				// the account does not have a mobile device associated with it
	k_EResultTimeNotSynced = 93,				// the time presented is out of range or tolerance
	k_EResultSmsCodeFailed = 94,				// SMS code failure (no match, none pending, etc.)
	k_EResultAccountLimitExceeded = 95,			// Too many accounts access this resource
	k_EResultAccountActivityLimitExceeded = 96,	// Too many changes to this account
	k_EResultPhoneActivityLimitExceeded = 97,	// Too many changes to this phone
	k_EResultRefundToWallet = 98,				// Cannot refund to payment method, must use wallet
	k_EResultEmailSendFailure = 99,				// Cannot send an email
	k_EResultNotSettled = 100,					// Can't perform operation till payment has settled
	k_EResultNeedCaptcha = 101,					// Needs to provide a valid captcha
	k_EResultGSLTDenied = 102,					// a game server login token owned by this token's owner has been banned
	k_EResultGSOwnerDenied = 103,				// game server owner is denied for other reason (account lock, community ban, vac ban, missing phone)
	k_EResultInvalidItemType = 104,				// the type of thing we were requested to act on is invalid
	k_EResultIPBanned = 105,					// the ip address has been banned from taking this action
	k_EResultGSLTExpired = 106,					// this token has expired from disuse; can be reset for use
	k_EResultInsufficientFunds = 107,			// user doesn't have enough wallet funds to complete the action
	k_EResultTooManyPending = 108,				// There are too many of this thing pending already
	k_EResultNoSiteLicensesFound = 109,			// No site licenses found
	k_EResultWGNetworkSendExceeded = 110,		// the WG couldn't send a response because we exceeded max network send size
} EResult;

/// Different methods of describing the identity of a network host
typedef enum ESteamNetworkingIdentityType
{
	// Dummy/empty/invalid.
	// Plese note that if we parse a string that we don't recognize
	// but that appears reasonable, we will NOT use this type.  Instead
	// we'll use k_ESteamNetworkingIdentityType_UnknownType.
	k_ESteamNetworkingIdentityType_Invalid = 0,

	//
	// Basic platform-specific identifiers.
	//
	k_ESteamNetworkingIdentityType_SteamID = 16, // 64-bit CSteamID

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
	k_ESteamNetworkingIdentityType_IPAddress = 1,

	// Generic string/binary blobs.  It's up to your app to interpret this.
	// This library can tell you if the remote host presented a certificate
	// signed by somebody you have chosen to trust, with this identity on it.
	// It's up to you to ultimately decide what this identity means.
	k_ESteamNetworkingIdentityType_GenericString = 2,
	k_ESteamNetworkingIdentityType_GenericBytes = 3,

	// This identity type is used when we parse a string that looks like is a
	// valid identity, just of a kind that we don't recognize.  In this case, we
	// can often still communicate with the peer!  Allowing such identities
	// for types we do not recognize useful is very useful for forward
	// compatibility.
	k_ESteamNetworkingIdentityType_UnknownType = 4,

	// Make sure this enum is stored in an int.
	k_ESteamNetworkingIdentityType__Force32bit = 0x7fffffff,
} ESteamNetworkingIdentityType;

// Max length of the buffer needed to hold IP formatted using ToString, including '\0'
// ([0123:4567:89ab:cdef:0123:4567:89ab:cdef]:12345)
enum { k_cchSteamNetworkingIPAddrMaxString = 48 };

#pragma pack(push,1)
/// Store an IP and port.  IPv6 is always used; IPv4 is represented using
/// "IPv4-mapped" addresses: IPv4 aa.bb.cc.dd => IPv6 ::ffff:aabb:ccdd
/// (RFC 4291 section 2.5.5.2.)
typedef struct SteamNetworkingIPAddr
{
	union
	{
		uint8_t m_ipv6[ 16 ];
		struct // IPv4 "mapped address" (rfc4038 section 4.2)
		{
			uint64_t m_8zeros;
			uint16_t m_0000;
			uint16_t m_ffff;
			uint8_t m_ip[ 4 ]; // NOTE: As bytes, i.e. network byte order
		} m_ipv4;
	} m_ip;
	uint16_t m_port; // Host byte order
} SteamNetworkingIPAddr;
#pragma pack(pop)

// Max sizes
enum {
	k_cchSteamNetworkingIdentityMaxString = 128, // Max length of the buffer needed to hold any identity, formatted in string format by ToString
	k_cchSteamNetworkingIdentityMaxGenericString = 32, // Max length of the string for generic string identities.  Including terminating '\0'
	k_cbMSteamNetworkingIdentityaxGenericBytes = 32,
};

/// An abstract way to represent the identity of a network host.  All identities can
/// be represented as simple string.  Furthermore, this string representation is actually
/// used on the wire in several places, even though it is less efficient, in order to
/// facilitate forward compatibility.  (Old client code can handle an identity type that
/// it doesn't understand.)
#pragma pack(push,1)
typedef struct SteamNetworkingIdentity
{
	/// Type of identity.
	ESteamNetworkingIdentityType m_eType;

	//
	// Internal representation.  Don't access this directly, use the accessors!
	//
	// Number of bytes that are relevant below.  This MUST ALWAYS be
	// set.  (Use the accessors!)  This is important to enable old code to work
	// with new identity types.
	int m_cbSize;
	union {
		uint64_t m_steamID64;
		char m_szGenericString[ k_cchSteamNetworkingIdentityMaxGenericString ];
		uint8_t m_genericBytes[ k_cbMSteamNetworkingIdentityaxGenericBytes ];
		char m_szUnknownRawString[ k_cchSteamNetworkingIdentityMaxString ];
		SteamNetworkingIPAddr m_ip;
		uint32_t m_reserved[ 32 ]; // Pad structure to leave easy room for future expansion
	} m_id;
} SteamNetworkingIdentity;
#pragma pack(pop)

/// Identifier used for a network location point of presence.  (E.g. a Valve data center.)
/// Typically you won't need to directly manipulate these.
typedef uint32_t SteamNetworkingPOPID;

/// High level connection status
typedef enum ESteamNetworkingConnectionState
{

	/// Dummy value used to indicate an error condition in the API.
	/// Specified connection doesn't exist or has already been closed.
	k_ESteamNetworkingConnectionState_None = 0,

	/// We are trying to establish whether peers can talk to each other,
	/// whether they WANT to talk to each other, perform basic auth,
	/// and exchange crypt keys.
	///
	/// - For connections on the "client" side (initiated locally):
	///   We're in the process of trying to establish a connection.
	///   Depending on the connection type, we might not know who they are.
	///   Note that it is not possible to tell if we are waiting on the
	///   network to complete handshake packets, or for the application layer
	///   to accept the connection.
	///
	/// - For connections on the "server" side (accepted through listen socket):
	///   We have completed some basic handshake and the client has presented
	///   some proof of identity.  The connection is ready to be accepted
	///   using AcceptConnection().
	///
	/// In either case, any unreliable packets sent now are almost certain
	/// to be dropped.  Attempts to receive packets are guaranteed to fail.
	/// You may send messages if the send mode allows for them to be queued.
	/// but if you close the connection before the connection is actually
	/// established, any queued messages will be discarded immediately.
	/// (We will not attempt to flush the queue and confirm delivery to the
	/// remote host, which ordinarily happens when a connection is closed.)
	k_ESteamNetworkingConnectionState_Connecting = 1,

	/// Some connection types use a back channel or trusted 3rd party
	/// for earliest communication.  If the server accepts the connection,
	/// then these connections switch into the rendezvous state.  During this
	/// state, we still have not yet established an end-to-end route (through
	/// the relay network), and so if you send any messages unreliable, they
	/// are going to be discarded.
	k_ESteamNetworkingConnectionState_FindingRoute = 2,

	/// We've received communications from our peer (and we know
	/// who they are) and are all good.  If you close the connection now,
	/// we will make our best effort to flush out any reliable sent data that
	/// has not been acknowledged by the peer.  (But note that this happens
	/// from within the application process, so unlike a TCP connection, you are
	/// not totally handing it off to the operating system to deal with it.)
	k_ESteamNetworkingConnectionState_Connected = 3,

	/// Connection has been closed by our peer, but not closed locally.
	/// The connection still exists from an API perspective.  You must close the
	/// handle to free up resources.  If there are any messages in the inbound queue,
	/// you may retrieve them.  Otherwise, nothing may be done with the connection
	/// except to close it.
	///
	/// This stats is similar to CLOSE_WAIT in the TCP state machine.
	k_ESteamNetworkingConnectionState_ClosedByPeer = 4,

	/// A disruption in the connection has been detected locally.  (E.g. timeout,
	/// local internet connection disrupted, etc.)
	///
	/// The connection still exists from an API perspective.  You must close the
	/// handle to free up resources.
	///
	/// Attempts to send further messages will fail.  Any remaining received messages
	/// in the queue are available.
	k_ESteamNetworkingConnectionState_ProblemDetectedLocally = 5
} ESteamNetworkingConnectionState;

/// Enumerate various causes of connection termination.  These are designed to work similar
/// to HTTP error codes: the numeric range gives you a rough classification as to the source
/// of the problem.
typedef enum ESteamNetConnectionEnd
{
	// Invalid/sentinel value
	k_ESteamNetConnectionEnd_Invalid = 0,

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
	k_ESteamNetConnectionEnd_App_Min = 1000,
		k_ESteamNetConnectionEnd_App_Generic = k_ESteamNetConnectionEnd_App_Min,
		// Use codes in this range for "normal" disconnection
	k_ESteamNetConnectionEnd_App_Max = 1999,

	// 2xxx: Application ended the connection in some sort of exceptional
	//       or unusual manner that might indicate a bug or configuration
	//       issue.
	// 
	k_ESteamNetConnectionEnd_AppException_Min = 2000,
		k_ESteamNetConnectionEnd_AppException_Generic = k_ESteamNetConnectionEnd_AppException_Min,
		// Use codes in this range for "unusual" disconnection
	k_ESteamNetConnectionEnd_AppException_Max = 2999,

	//
	// System codes.  These will be returned by the system when
	// the connection state is k_ESteamNetworkingConnectionState_ClosedByPeer
	// or k_ESteamNetworkingConnectionState_ProblemDetectedLocally.  It is
	// illegal to pass a code in this range to ISteamNetworkingSockets::CloseConnection
	//

	// 3xxx: Connection failed or ended because of problem with the
	//       local host or their connection to the Internet.
	k_ESteamNetConnectionEnd_Local_Min = 3000,

		// You cannot do what you want to do because you're running in offline mode.
		k_ESteamNetConnectionEnd_Local_OfflineMode = 3001,

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
		k_ESteamNetConnectionEnd_Local_ManyRelayConnectivity = 3002,

		// A hosted server is having trouble talking to the relay
		// that the client was using, so the problem is most likely
		// on our end
		k_ESteamNetConnectionEnd_Local_HostedServerPrimaryRelay = 3003,

		// We're not able to get the network config.  This is
		// *almost* always a local issue, since the network config
		// comes from the CDN, which is pretty darn reliable.
		k_ESteamNetConnectionEnd_Local_NetworkConfig = 3004,

		// Steam rejected our request because we don't have rights
		// to do this.
		k_ESteamNetConnectionEnd_Local_Rights = 3005,

	k_ESteamNetConnectionEnd_Local_Max = 3999,

	// 4xxx: Connection failed or ended, and it appears that the
	//       cause does NOT have to do with the local host or their
	//       connection to the Internet.  It could be caused by the
	//       remote host, or it could be somewhere in between.
	k_ESteamNetConnectionEnd_Remote_Min = 4000,

		// The connection was lost, and as far as we can tell our connection
		// to relevant services (relays) has not been disrupted.  This doesn't
		// mean that the problem is "their fault", it just means that it doesn't
		// appear that we are having network issues on our end.
		k_ESteamNetConnectionEnd_Remote_Timeout = 4001,

		// Something was invalid with the cert or crypt handshake
		// info you gave me, I don't understand or like your key types,
		// etc.
		k_ESteamNetConnectionEnd_Remote_BadCrypt = 4002,

		// You presented me with a cert that was I was able to parse
		// and *technically* we could use encrypted communication.
		// But there was a problem that prevents me from checking your identity
		// or ensuring that somebody int he middle can't observe our communication.
		// E.g.: - the CA key was missing (and I don't accept unsigned certs)
		// - The CA key isn't one that I trust,
		// - The cert doesn't was appropriately restricted by app, user, time, data center, etc.
		// - The cert wasn't issued to you.
		// - etc
		k_ESteamNetConnectionEnd_Remote_BadCert = 4003,

		// We couldn't rendezvous with the remote host because
		// they aren't logged into Steam
		k_ESteamNetConnectionEnd_Remote_NotLoggedIn = 4004,

		// We couldn't rendezvous with the remote host because
		// they aren't running the right application.
		k_ESteamNetConnectionEnd_Remote_NotRunningApp = 4005,

		// Something wrong with the protocol version you are using.
		// (Probably the code you are running is too old.)
		k_ESteamNetConnectionEnd_Remote_BadProtocolVersion = 4006,

	k_ESteamNetConnectionEnd_Remote_Max = 4999,

	// 5xxx: Connection failed for some other reason.
	k_ESteamNetConnectionEnd_Misc_Min = 5000,

		// A failure that isn't necessarily the result of a software bug,
		// but that should happen rarely enough that it isn't worth specifically
		// writing UI or making a localized message for.
		// The debug string should contain further details.
		k_ESteamNetConnectionEnd_Misc_Generic = 5001,

		// Generic failure that is most likely a software bug.
		k_ESteamNetConnectionEnd_Misc_InternalError = 5002,

		// The connection to the remote host timed out, but we
		// don't know if the problem is on our end, in the middle,
		// or on their end.
		k_ESteamNetConnectionEnd_Misc_Timeout = 5003,

		// We're having trouble talking to the relevant relay.
		// We don't have enough information to say whether the
		// problem is on our end or not.
		k_ESteamNetConnectionEnd_Misc_RelayConnectivity = 5004,

		// There's some trouble talking to Steam.
		k_ESteamNetConnectionEnd_Misc_SteamConnectivity = 5005,

		// A server in a dedicated hosting situation has no relay sessions
		// active with which to talk back to a client.  (It's the client's
		// job to open and maintain those sessions.)
		k_ESteamNetConnectionEnd_Misc_NoRelaySessionsToClient = 5006,

	k_ESteamNetConnectionEnd_Misc_Max = 5999,

	k_ESteamNetConnectionEnd__Force32Bit = 0x7fffffff
} ESteamNetConnectionEnd;

/// Max length, in bytes (including null terminator) of the reason string
/// when a connection is closed.
enum { k_cchSteamNetworkingMaxConnectionCloseReason = 128 };

/// Max length, in bytes (include null terminator) of debug description
/// of a connection.
enum { k_cchSteamNetworkingMaxConnectionDescription = 128 };

/// Describe the state of a connection.
PRAGMA_PACK_PUSH
typedef struct SteamNetConnectionInfo_t
{

	/// Who is on the other end?  Depending on the connection type and phase of the connection, we might not know
	SteamNetworkingIdentity m_identityRemote;

	/// Arbitrary user data set by the local application code
	int64_t m_nUserData;

	/// Handle to listen socket this was connected on, or k_HSteamListenSocket_Invalid if we initiated the connection
	HSteamListenSocket m_hListenSocket;

	/// Remote address.  Might be all 0's if we don't know it, or if this is N/A.
	/// (E.g. Basically everything except direct UDP connection.)
	SteamNetworkingIPAddr m_addrRemote;
	uint16_t m__pad1;

	/// What data center is the remote host in?  (0 if we don't know.)
	SteamNetworkingPOPID m_idPOPRemote;

	/// What relay are we using to communicate with the remote host?
	/// (0 if not applicable.)
	SteamNetworkingPOPID m_idPOPRelay;

	/// High level state of the connection
	ESteamNetworkingConnectionState m_eState;

	/// Basic cause of the connection termination or problem.
	/// See ESteamNetConnectionEnd for the values used
	int m_eEndReason;

	/// Human-readable, but non-localized explanation for connection
	/// termination or problem.  This is intended for debugging /
	/// diagnostic purposes only, not to display to users.  It might
	/// have some details specific to the issue.
	char m_szEndDebug[ k_cchSteamNetworkingMaxConnectionCloseReason ];

	/// Debug description.  This includes the connection handle,
	/// connection type (and peer information), and the app name.
	/// This string is used in various internal logging messages
	char m_szConnectionDescription[ k_cchSteamNetworkingMaxConnectionDescription ];

	/// Internal stuff, room to change API easily
	uint32_t reserved[64];
} SteamNetConnectionInfo_t;
PRAGMA_PACK_POP

/// A local timestamp.  You can subtract two timestamps to get the number of elapsed
/// microseconds.  This is guaranteed to increase over time during the lifetime
/// of a process, but not globally across runs.  You don't need to worry about
/// the value wrapping around.  Note that the underlying clock might not actually have
/// microsecond resolution.
typedef int64_t SteamNetworkingMicroseconds;

/// Quick connection state, pared down to something you could call
/// more frequently without it being too big of a perf hit.
PRAGMA_PACK_PUSH
typedef struct SteamNetworkingQuickConnectionStatus
{

	/// High level state of the connection
	ESteamNetworkingConnectionState m_eState;

	/// Current ping (ms)
	int m_nPing;

	/// Connection quality measured locally, 0...1.  (Percentage of packets delivered
	/// end-to-end in order).
	float m_flConnectionQualityLocal;

	/// Packet delivery success rate as observed from remote host
	float m_flConnectionQualityRemote;

	/// Current data rates from recent history.
	float m_flOutPacketsPerSec;
	float m_flOutBytesPerSec;
	float m_flInPacketsPerSec;
	float m_flInBytesPerSec;

	/// Estimate rate that we believe that we can send data to our peer.
	/// Note that this could be significantly higher than m_flOutBytesPerSec,
	/// meaning the capacity of the channel is higher than you are sending data.
	/// (That's OK!)
	int m_nSendRateBytesPerSecond;

	/// Number of bytes pending to be sent.  This is data that you have recently
	/// requested to be sent but has not yet actually been put on the wire.  The
	/// reliable number ALSO includes data that was previously placed on the wire,
	/// but has now been scheduled for re-transmission.  Thus, it's possible to
	/// observe m_cbPendingReliable increasing between two checks, even if no
	/// calls were made to send reliable data between the checks.  Data that is
	/// awaiting the Nagle delay will appear in these numbers.
	int m_cbPendingUnreliable;
	int m_cbPendingReliable;

	/// Number of bytes of reliable data that has been placed the wire, but
	/// for which we have not yet received an acknowledgment, and thus we may
	/// have to re-transmit.
	int m_cbSentUnackedReliable;

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
	SteamNetworkingMicroseconds m_usecQueueTime;

	/// Internal stuff, room to change API easily
	uint32_t reserved[16];
} SteamNetworkingQuickConnectionStatus;
PRAGMA_PACK_POP

/// Describe the status of a particular network resource
typedef enum ESteamNetworkingAvailability
{
	// Negative values indicate a problem.
	//
	// In general, we will not automatically retry unless you take some action that
	// depends on of requests this resource, such as querying the status, attempting
	// to initiate a connection, receive a connection, etc.  If you do not take any
	// action at all, we do not automatically retry in the background.
	k_ESteamNetworkingAvailability_CannotTry = -102,		// A dependent resource is missing, so this service is unavailable.  (E.g. we cannot talk to routers because Internet is down or we don't have the network config.)
	k_ESteamNetworkingAvailability_Failed = -101,			// We have tried for enough time that we would expect to have been successful by now.  We have never been successful
	k_ESteamNetworkingAvailability_Previously = -100,		// We tried and were successful at one time, but now it looks like we have a problem

	k_ESteamNetworkingAvailability_Retrying = -10,		// We previously failed and are currently retrying

	// Not a problem, but not ready either
	k_ESteamNetworkingAvailability_NeverTried = 1,		// We don't know because we haven't ever checked/tried
	k_ESteamNetworkingAvailability_Waiting = 2,			// We're waiting on a dependent resource to be acquired.  (E.g. we cannot obtain a cert until we are logged into Steam.  We cannot measure latency to relays until we have the network config.)
	k_ESteamNetworkingAvailability_Attempting = 3,		// We're actively trying now, but are not yet successful.

	k_ESteamNetworkingAvailability_Current = 100,			// Resource is online/available


	k_ESteamNetworkingAvailability_Unknown = 0,			// Internal dummy/sentinel, or value is not applicable in this context
	k_ESteamNetworkingAvailability__Force32bit = 0x7fffffff,
} ESteamNetworkingAvailability;

enum {
    k_iSteamNetworkingSocketsCallbacks        = 1220,
    k_SteamNetConnectionStatusChangedCallback = k_iSteamNetworkingSocketsCallbacks + 1,
    k_SteamNetAuthenticationStatus            = k_iSteamNetworkingSocketsCallbacks + 2,
};

/// A struct used to describe our readiness to participate in authenticated,
/// encrypted communication.  In order to do this we need:
///
/// - The list of trusted CA certificates that might be relevant for this
///   app.
/// - A valid certificate issued by a CA.
///
/// This callback is posted whenever the state of our readiness changes.
PRAGMA_PACK_PUSH
typedef struct SteamNetAuthenticationStatus_t
{ 
	/// Status
	ESteamNetworkingAvailability m_eAvail;

	/// Non-localized English language status.  For diagnostic/debugging
	/// purposes only.
	char m_debugMsg[ 256 ];
} SteamNetAuthenticationStatus_t;
PRAGMA_PACK_POP

/// Handle used to identify a poll group, used to query many
/// connections at once efficiently.
typedef uint32_t HSteamNetPollGroup;
enum { k_HSteamNetPollGroup_Invalid = 0 };

/// Max length of diagnostic error message
enum { k_cchMaxSteamNetworkingErrMsg = 1024 };

/// Used to return English-language diagnostic error messages to caller.
/// (For debugging or spewing to a console, etc.  Not intended for UI.)
typedef char SteamNetworkingErrMsg[ k_cchMaxSteamNetworkingErrMsg ];

// Callback dispatch mechanism when using the lib in standalone mode.
PRAGMA_PACK_PUSH
typedef struct SteamNetConnectionStatusChangedCallback_t
{ 
	/// Connection handle
	HSteamNetConnection m_hConn;

	/// Full connection info
	SteamNetConnectionInfo_t m_info;

	/// Previous state.  (Current state is in m_info.m_eState)
	ESteamNetworkingConnectionState m_eOldState;
} SteamNetConnectionStatusChangedCallback_t;
PRAGMA_PACK_POP

/// Detail level for diagnostic output callback.
/// See ISteamNetworkingUtils::SetDebugOutputFunction
typedef enum ESteamNetworkingSocketsDebugOutputType
{
	k_ESteamNetworkingSocketsDebugOutputType_None = 0,
	k_ESteamNetworkingSocketsDebugOutputType_Bug = 1, // You used the API incorrectly, or an internal error happened
	k_ESteamNetworkingSocketsDebugOutputType_Error = 2, // Run-time error condition that isn't the result of a bug.  (E.g. we are offline, cannot bind a port, etc)
	k_ESteamNetworkingSocketsDebugOutputType_Important = 3, // Nothing is wrong, but this is an important notification
	k_ESteamNetworkingSocketsDebugOutputType_Warning = 4,
	k_ESteamNetworkingSocketsDebugOutputType_Msg = 5, // Recommended amount
	k_ESteamNetworkingSocketsDebugOutputType_Verbose = 6, // Quite a bit
	k_ESteamNetworkingSocketsDebugOutputType_Debug = 7, // Practically everything
	k_ESteamNetworkingSocketsDebugOutputType_Everything = 8, // Wall of text, detailed packet contents breakdown, etc

	k_ESteamNetworkingSocketsDebugOutputType__Force32Bit = 0x7fffffff
} ESteamNetworkingSocketsDebugOutputType;

/// Setup callback for debug output, and the desired verbosity you want.
typedef void (*FSteamNetworkingSocketsDebugOutput)( ESteamNetworkingSocketsDebugOutputType nType, const char *pszMsg );

/// Configuration values can be applied to different types of objects.
typedef enum ESteamNetworkingConfigScope
{

	/// Get/set global option, or defaults.  Even options that apply to more specific scopes
	/// have global scope, and you may be able to just change the global defaults.  If you
	/// need different settings per connection (for example), then you will need to set those
	/// options at the more specific scope.
	k_ESteamNetworkingConfig_Global = 1,

	/// Some options are specific to a particular interface.  Note that all connection
	/// and listen socket settings can also be set at the interface level, and they will
	/// apply to objects created through those interfaces.
	k_ESteamNetworkingConfig_SocketsInterface = 2,

	/// Options for a listen socket.  Listen socket options can be set at the interface layer,
	/// if  you have multiple listen sockets and they all use the same options.
	/// You can also set connection options on a listen socket, and they set the defaults
	/// for all connections accepted through this listen socket.  (They will be used if you don't
	/// set a connection option.)
	k_ESteamNetworkingConfig_ListenSocket = 3,

	/// Options for a specific connection.
	k_ESteamNetworkingConfig_Connection = 4,

	k_ESteamNetworkingConfigScope__Force32Bit = 0x7fffffff
} ESteamNetworkingConfigScope;

/// Return value of ISteamNetworkintgUtils::GetConfigValue
typedef enum ESteamNetworkingGetConfigValueResult
{
	k_ESteamNetworkingGetConfigValue_BadValue = -1,	// No such configuration value
	k_ESteamNetworkingGetConfigValue_BadScopeObj = -2,	// Bad connection handle, etc
	k_ESteamNetworkingGetConfigValue_BufferTooSmall = -3, // Couldn't fit the result in your buffer
	k_ESteamNetworkingGetConfigValue_OK = 1,
	k_ESteamNetworkingGetConfigValue_OKInherited = 2, // A value was not set at this level, but the effective (inherited) value was returned.

	k_ESteamNetworkingGetConfigValueResult__Force32Bit = 0x7fffffff
} ESteamNetworkingGetConfigValueResult;

typedef uint64_t uint64_steamid; // Used when passing or returning CSteamID

//
// Flags used to set options for message sending
//
enum {
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
	k_nSteamNetworkingSend_Unreliable = 0,

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
	k_nSteamNetworkingSend_NoNagle = 1,

	// Send a message unreliably, bypassing Nagle's algorithm for this message and any messages
	// currently pending on the Nagle timer.  This is equivalent to using k_ESteamNetworkingSend_Unreliable
	// and then immediately flushing the messages using ISteamNetworkingSockets::FlushMessagesOnConnection
	// or ISteamNetworkingMessages::FlushMessagesToUser.  (But using this flag is more efficient since you
	// only make one API call.)
	k_nSteamNetworkingSend_UnreliableNoNagle = k_nSteamNetworkingSend_Unreliable|k_nSteamNetworkingSend_NoNagle,

	// If the message cannot be sent very soon (because the connection is still doing some initial
	// handshaking, route negotiations, etc), then just drop it.  This is only applicable for unreliable
	// messages.  Using this flag on reliable messages is invalid.
	k_nSteamNetworkingSend_NoDelay = 4,

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
	k_nSteamNetworkingSend_UnreliableNoDelay = k_nSteamNetworkingSend_Unreliable|k_nSteamNetworkingSend_NoDelay|k_nSteamNetworkingSend_NoNagle,

	// Reliable message send. Can send up to k_cbMaxSteamNetworkingSocketsMessageSizeSend bytes in a single message. 
	// Does fragmentation/re-assembly of messages under the hood, as well as a sliding window for
	// efficient sends of large chunks of data.
	//
	// The Nagle algorithm is used.  See notes on k_ESteamNetworkingSendType_Unreliable for more details.
	// See k_ESteamNetworkingSendType_ReliableNoNagle, ISteamNetworkingSockets::FlushMessagesOnConnection,
	// ISteamNetworkingMessages::FlushMessagesToUser
	//
	// Migration note: This is NOT the same as k_EP2PSendReliable, it's more like k_EP2PSendReliableWithBuffering
	k_nSteamNetworkingSend_Reliable = 8,

	// Send a message reliably, but bypass Nagle's algorithm.
	//
	// Migration note: This is equivalent to k_EP2PSendReliable
	k_nSteamNetworkingSend_ReliableNoNagle = k_nSteamNetworkingSend_Reliable|k_nSteamNetworkingSend_NoNagle,

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
	k_nSteamNetworkingSend_UseCurrentThread = 16,
};

enum {
	/// Max size of a single message that we can SEND.
	/// Note: We might be wiling to receive larger messages,
	/// and our peer might, too.
	 k_cbMaxSteamNetworkingSocketsMessageSizeSend = 512 * 1024,

	 // Max size of a message that we are wiling to *receive*.
	k_cbMaxMessageSizeRecv = k_cbMaxSteamNetworkingSocketsMessageSizeSend*2
};

/// A message that has been received.
typedef struct SteamNetworkingMessage_t
{
	/// Message payload
	void *m_pData;

	/// Size of the payload.
	int m_cbSize;

	/// For messages received on connections: what connection did this come from?
	/// For outgoing messages: what connection to send it to?
	/// Not used when using the ISteamNetworkingMessages interface
	HSteamNetConnection m_conn;

	/// For inbound messages: Who sent this to us?
	/// For outbound messages on connections: not used.
	/// For outbound messages on the ad-hoc ISteamNetworkingMessages interface: who should we send this to?
	SteamNetworkingIdentity m_identityPeer;

	/// For messages received on connections, this is the user data
	/// associated with the connection.
	///
	/// This is *usually* the same as calling GetConnection() and then
	/// fetching the user data associated with that connection, but for
	/// the following subtle differences:
	///
	/// - This user data will match the connection's user data at the time
	///   is captured at the time the message is returned by the API.
	///   If you subsequently change the userdata on the connection,
	///   this won't be updated.
	/// - This is an inline call, so it's *much* faster.
	/// - You might have closed the connection, so fetching the user data
	///   would not be possible.
	///
	/// Not used when sending messages, 
	int64_t m_nConnUserData;

	/// Local timestamp when the message was received
	/// Not used for outbound messages.
	SteamNetworkingMicroseconds m_usecTimeReceived;

	/// Message number assigned by the sender.
	/// This is not used for outbound messages
	int64_t m_nMessageNumber;

	/// Function used to free up m_pData.  This mechanism exists so that
	/// apps can create messages with buffers allocated from their own
	/// heap, and pass them into the library.  This function will
	/// usually be something like:
	///
	/// free( pMsg->m_pData );
	void (*m_pfnFreeData)( struct SteamNetworkingMessage_t *pMsg );

	/// Function to used to decrement the internal reference count and, if
	/// it's zero, release the message.  You should not set this function pointer,
	/// or need to access this directly!  Use the Release() function instead!
	void (*m_pfnRelease)( struct SteamNetworkingMessage_t *pMsg );

	/// When using ISteamNetworkingMessages, the channel number the message was received on
	/// (Not used for messages sent or received on "connections")
	int m_nChannel;

	/// Bitmask of k_nSteamNetworkingSend_xxx flags.
	/// For received messages, only the k_nSteamNetworkingSend_Reliable bit is valid.
	/// For outbound messages, all bits are relevant
	int m_nFlags;

	/// Arbitrary user data that you can use when sending messages using
	/// ISteamNetworkingUtils::AllocateMessage and ISteamNetworkingSockets::SendMessage.
	/// (The callback you set in m_pfnFreeData might use this field.)
	///
	/// Not used for received messages.
	int64_t m_nUserData;
} SteamNetworkingMessage_t;

// GameNetworkingSockets
extern bool GameNetworkingSockets_Init( const SteamNetworkingIdentity *pIdentity, SteamNetworkingErrMsg *errMsg );
extern void GameNetworkingSockets_Kill();

// ISteamNetworkingSockets
extern ISteamNetworkingSockets *SteamAPI_SteamNetworkingSockets_v008();
extern HSteamListenSocket SteamAPI_ISteamNetworkingSockets_CreateListenSocketIP( ISteamNetworkingSockets* self, const SteamNetworkingIPAddr *localAddress, int nOptions, const SteamNetworkingConfigValue_t * pOptions );
extern HSteamNetConnection SteamAPI_ISteamNetworkingSockets_ConnectByIPAddress( ISteamNetworkingSockets* self, const SteamNetworkingIPAddr *address, int nOptions, const SteamNetworkingConfigValue_t * pOptions );
extern EResult SteamAPI_ISteamNetworkingSockets_AcceptConnection( ISteamNetworkingSockets* self, HSteamNetConnection hConn );
extern bool SteamAPI_ISteamNetworkingSockets_CloseConnection( ISteamNetworkingSockets* self, HSteamNetConnection hPeer, int nReason, const char * pszDebug, bool bEnableLinger );
extern bool SteamAPI_ISteamNetworkingSockets_CloseListenSocket( ISteamNetworkingSockets* self, HSteamListenSocket hSocket );
extern bool SteamAPI_ISteamNetworkingSockets_SetConnectionUserData( ISteamNetworkingSockets* self, HSteamNetConnection hPeer, int64_t nUserData );
extern int64_t SteamAPI_ISteamNetworkingSockets_GetConnectionUserData( ISteamNetworkingSockets* self, HSteamNetConnection hPeer );
extern void SteamAPI_ISteamNetworkingSockets_SetConnectionName( ISteamNetworkingSockets* self, HSteamNetConnection hPeer, const char * pszName );
extern bool SteamAPI_ISteamNetworkingSockets_GetConnectionName( ISteamNetworkingSockets* self, HSteamNetConnection hPeer, char * pszName, int nMaxLen );
extern EResult SteamAPI_ISteamNetworkingSockets_SendMessageToConnection( ISteamNetworkingSockets* self, HSteamNetConnection hConn, const void * pData, uint32_t cbData, int nSendFlags, int64_t * pOutMessageNumber );
extern void SteamAPI_ISteamNetworkingSockets_SendMessages( ISteamNetworkingSockets* self, int nMessages, SteamNetworkingMessage_t *const * pMessages, int64_t * pOutMessageNumberOrResult );
extern EResult SteamAPI_ISteamNetworkingSockets_FlushMessagesOnConnection( ISteamNetworkingSockets* self, HSteamNetConnection hConn );
extern int SteamAPI_ISteamNetworkingSockets_ReceiveMessagesOnConnection( ISteamNetworkingSockets* self, HSteamNetConnection hConn, SteamNetworkingMessage_t ** ppOutMessages, int nMaxMessages );
extern bool SteamAPI_ISteamNetworkingSockets_GetConnectionInfo( ISteamNetworkingSockets* self, HSteamNetConnection hConn, SteamNetConnectionInfo_t * pInfo );
extern bool SteamAPI_ISteamNetworkingSockets_GetQuickConnectionStatus( ISteamNetworkingSockets* self, HSteamNetConnection hConn, SteamNetworkingQuickConnectionStatus * pStats );
extern int SteamAPI_ISteamNetworkingSockets_GetDetailedConnectionStatus( ISteamNetworkingSockets* self, HSteamNetConnection hConn, char * pszBuf, int cbBuf );
extern bool SteamAPI_ISteamNetworkingSockets_GetListenSocketAddress( ISteamNetworkingSockets* self, HSteamListenSocket hSocket, SteamNetworkingIPAddr * address );
extern bool SteamAPI_ISteamNetworkingSockets_CreateSocketPair( ISteamNetworkingSockets* self, HSteamNetConnection * pOutConnection1, HSteamNetConnection * pOutConnection2, bool bUseNetworkLoopback, const SteamNetworkingIdentity * pIdentity1, const SteamNetworkingIdentity * pIdentity2 );
extern bool SteamAPI_ISteamNetworkingSockets_GetIdentity( ISteamNetworkingSockets* self, SteamNetworkingIdentity * pIdentity );
extern ESteamNetworkingAvailability SteamAPI_ISteamNetworkingSockets_InitAuthentication( ISteamNetworkingSockets* self );
extern ESteamNetworkingAvailability SteamAPI_ISteamNetworkingSockets_GetAuthenticationStatus( ISteamNetworkingSockets* self, SteamNetAuthenticationStatus_t * pDetails );
extern HSteamNetPollGroup SteamAPI_ISteamNetworkingSockets_CreatePollGroup( ISteamNetworkingSockets* self );
extern bool SteamAPI_ISteamNetworkingSockets_DestroyPollGroup( ISteamNetworkingSockets* self, HSteamNetPollGroup hPollGroup );
extern bool SteamAPI_ISteamNetworkingSockets_SetConnectionPollGroup( ISteamNetworkingSockets* self, HSteamNetConnection hConn, HSteamNetPollGroup hPollGroup );
extern int SteamAPI_ISteamNetworkingSockets_ReceiveMessagesOnPollGroup( ISteamNetworkingSockets* self, HSteamNetPollGroup hPollGroup, SteamNetworkingMessage_t ** ppOutMessages, int nMaxMessages );
extern bool SteamAPI_ISteamNetworkingSockets_GetCertificateRequest( ISteamNetworkingSockets* self, int * pcbBlob, void * pBlob, SteamNetworkingErrMsg *errMsg );
extern bool SteamAPI_ISteamNetworkingSockets_SetCertificate( ISteamNetworkingSockets* self, const void * pCertificate, int cbCertificate, SteamNetworkingErrMsg *errMsg );

// Callback dispatch mechanism when using the lib in standalone mode.
typedef void (*FSteamNetConnectionStatusChangedCallback)( SteamNetConnectionStatusChangedCallback_t *pInfo, intptr_t context );
extern void SteamAPI_ISteamNetworkingSockets_RunConnectionStatusChangedCallbacks ( intptr_t instancePtr, FSteamNetConnectionStatusChangedCallback callback, intptr_t context );


// ISteamNetworkingUtils
extern ISteamNetworkingUtils *SteamAPI_SteamNetworkingUtils_v003();
extern SteamNetworkingMessage_t * SteamAPI_ISteamNetworkingUtils_AllocateMessage( ISteamNetworkingUtils* self, int cbAllocateBuffer );
extern SteamNetworkingMicroseconds SteamAPI_ISteamNetworkingUtils_GetLocalTimestamp( ISteamNetworkingUtils* self );
extern void SteamAPI_ISteamNetworkingUtils_SetDebugOutputFunction( ISteamNetworkingUtils* self, ESteamNetworkingSocketsDebugOutputType eDetailLevel, FSteamNetworkingSocketsDebugOutput pfnFunc );
extern bool SteamAPI_ISteamNetworkingUtils_SetGlobalConfigValueInt32( ISteamNetworkingUtils* self, ESteamNetworkingConfigValue eValue, int32_t val );
extern bool SteamAPI_ISteamNetworkingUtils_SetGlobalConfigValueFloat( ISteamNetworkingUtils* self, ESteamNetworkingConfigValue eValue, float val );
extern bool SteamAPI_ISteamNetworkingUtils_SetGlobalConfigValueString( ISteamNetworkingUtils* self, ESteamNetworkingConfigValue eValue, const char * val );
extern bool SteamAPI_ISteamNetworkingUtils_SetConnectionConfigValueInt32( ISteamNetworkingUtils* self, HSteamNetConnection hConn, ESteamNetworkingConfigValue eValue, int32_t val );
extern bool SteamAPI_ISteamNetworkingUtils_SetConnectionConfigValueFloat( ISteamNetworkingUtils* self, HSteamNetConnection hConn, ESteamNetworkingConfigValue eValue, float val );
extern bool SteamAPI_ISteamNetworkingUtils_SetConnectionConfigValueString( ISteamNetworkingUtils* self, HSteamNetConnection hConn, ESteamNetworkingConfigValue eValue, const char * val );
extern bool SteamAPI_ISteamNetworkingUtils_SetConfigValue( ISteamNetworkingUtils* self, ESteamNetworkingConfigValue eValue, ESteamNetworkingConfigScope eScopeType, intptr_t scopeObj, ESteamNetworkingConfigDataType eDataType, const void * pArg );
extern bool SteamAPI_ISteamNetworkingUtils_SetConfigValueStruct( ISteamNetworkingUtils* self, const SteamNetworkingConfigValue_t *opt, ESteamNetworkingConfigScope eScopeType, intptr_t scopeObj );
extern ESteamNetworkingGetConfigValueResult SteamAPI_ISteamNetworkingUtils_GetConfigValue( ISteamNetworkingUtils* self, ESteamNetworkingConfigValue eValue, ESteamNetworkingConfigScope eScopeType, intptr_t scopeObj, ESteamNetworkingConfigDataType * pOutDataType, void * pResult, size_t * cbResult );
extern bool SteamAPI_ISteamNetworkingUtils_GetConfigValueInfo( ISteamNetworkingUtils* self, ESteamNetworkingConfigValue eValue, const char ** pOutName, ESteamNetworkingConfigDataType * pOutDataType, ESteamNetworkingConfigScope * pOutScope, ESteamNetworkingConfigValue * pOutNextValue );
extern ESteamNetworkingConfigValue SteamAPI_ISteamNetworkingUtils_GetFirstConfigValue( ISteamNetworkingUtils* self );

// SteamNetworkingIPAddr
extern void SteamAPI_SteamNetworkingIPAddr_Clear( SteamNetworkingIPAddr* self );
extern bool SteamAPI_SteamNetworkingIPAddr_IsIPv6AllZeros( SteamNetworkingIPAddr* self );
extern void SteamAPI_SteamNetworkingIPAddr_SetIPv6( SteamNetworkingIPAddr* self, const uint8_t * ipv6, uint16_t nPort );
extern void SteamAPI_SteamNetworkingIPAddr_SetIPv4( SteamNetworkingIPAddr* self, uint32_t nIP, uint16_t nPort );
extern bool SteamAPI_SteamNetworkingIPAddr_IsIPv4( SteamNetworkingIPAddr* self );
extern uint32_t SteamAPI_SteamNetworkingIPAddr_GetIPv4( SteamNetworkingIPAddr* self );
extern void SteamAPI_SteamNetworkingIPAddr_SetIPv6LocalHost( SteamNetworkingIPAddr* self, uint16_t nPort );
extern bool SteamAPI_SteamNetworkingIPAddr_IsLocalHost( SteamNetworkingIPAddr* self );
extern bool SteamAPI_SteamNetworkingIPAddr_IsEqualTo( SteamNetworkingIPAddr* self, const SteamNetworkingIPAddr *x );
extern void SteamAPI_SteamNetworkingIPAddr_ToString( const SteamNetworkingIPAddr *pAddr, char *buf, size_t cbBuf, bool bWithPort );
extern bool SteamAPI_SteamNetworkingIPAddr_ParseString( SteamNetworkingIPAddr *pAddr, const char *pszStr );

// SteamNetworkingIdentity
extern void SteamAPI_SteamNetworkingIdentity_Clear( SteamNetworkingIdentity* self );
extern bool SteamAPI_SteamNetworkingIdentity_IsInvalid( SteamNetworkingIdentity* self );
extern void SteamAPI_SteamNetworkingIdentity_SetSteamID( SteamNetworkingIdentity* self, uint64_steamid steamID );
extern uint64_steamid SteamAPI_SteamNetworkingIdentity_GetSteamID( SteamNetworkingIdentity* self );
extern void SteamAPI_SteamNetworkingIdentity_SetSteamID64( SteamNetworkingIdentity* self, uint64_t steamID );
extern uint64_t SteamAPI_SteamNetworkingIdentity_GetSteamID64( SteamNetworkingIdentity* self );
extern void SteamAPI_SteamNetworkingIdentity_SetIPAddr( SteamNetworkingIdentity* self, const SteamNetworkingIPAddr *addr );
extern const SteamNetworkingIPAddr * SteamAPI_SteamNetworkingIdentity_GetIPAddr( SteamNetworkingIdentity* self );
extern void SteamAPI_SteamNetworkingIdentity_SetLocalHost( SteamNetworkingIdentity* self );
extern bool SteamAPI_SteamNetworkingIdentity_IsLocalHost( SteamNetworkingIdentity* self );
extern bool SteamAPI_SteamNetworkingIdentity_SetGenericString( SteamNetworkingIdentity* self, const char * pszString );
extern const char * SteamAPI_SteamNetworkingIdentity_GetGenericString( SteamNetworkingIdentity* self );
extern bool SteamAPI_SteamNetworkingIdentity_SetGenericBytes( SteamNetworkingIdentity* self, const void * data, uint32_t cbLen );
extern const uint8_t * SteamAPI_SteamNetworkingIdentity_GetGenericBytes( SteamNetworkingIdentity* self, int *cbLen );
extern bool SteamAPI_SteamNetworkingIdentity_IsEqualTo( SteamNetworkingIdentity* self, const SteamNetworkingIdentity *x );
extern void SteamAPI_SteamNetworkingIdentity_ToString( const SteamNetworkingIdentity *pIdentity, char *buf, size_t cbBuf );
extern bool SteamAPI_SteamNetworkingIdentity_ParseString( SteamNetworkingIdentity *pIdentity, size_t sizeofIdentity, const char *pszStr );

// SteamNetworkingMessage_t
extern void SteamAPI_SteamNetworkingMessage_t_Release( SteamNetworkingMessage_t* self );
