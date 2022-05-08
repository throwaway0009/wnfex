#pragma once
#include <Windows.h>

#define WNF_STATE_KEY                0x41C64E6DA3BC0074

// kernel-mode structures
#define WNF_NODE_SCOPE_MAP           0x901
#define WNF_NODE_SCOPE_INSTANCE      0x902
#define WNF_NODE_NAME_INSTANCE       0x903
#define WNF_NODE_STATE_DATA          0x904
#define WNF_NODE_SUBSCRIBE_INSTANCE  0x905
#define WNF_NODE_PROCESS_CONTEXT     0x906

// user-mode structures
#define WNF_NODE_SUBSCRIPTION_TABLE  0x911
#define WNF_NODE_NAME_SUBSCRIPTION   0x912
#define WNF_NODE_SERIALIZATION_GROUP 0x913
#define WNF_NODE_USER_SUBSCRIPTION   0x914

typedef enum _WNF_STATE_NAME_LIFETIME 
{
    WnfWellKnownStateName = 0x0,
    WnfPermanentStateName = 0x1,
    WnfPersistentStateName = 0x2,
    WnfTemporaryStateName = 0x3
} WNF_STATE_NAME_LIFETIME;

typedef enum _WNF_DATA_SCOPE 
{
    WnfDataScopeSystem = 0x0,
    WnfDataScopeSession = 0x1,
    WnfDataScopeUser = 0x2,
    WnfDataScopeProcess = 0x3,
    WnfDataScopeMachine = 0x4
} WNF_DATA_SCOPE;

typedef enum _WNF_STATE_NAME_INFORMATION 
{
    WnfInfoStateNameExist = 0x0,
    WnfInfoSubscribersPresent = 0x1,
    WnfInfoIsQuiescent = 0x2
} WNF_STATE_NAME_INFORMATION;

typedef struct _WNF_STATE_NAME_INTERNAL 
{
    ULONG64                           Version : 4;
    ULONG64                           NameLifetime : 2;
    ULONG64                           DataScope : 4;
    ULONG64                           PermanentData : 1;
    ULONG64                           Unique : 53;
} WNF_STATE_NAME_INTERNAL, * PWNF_STATE_NAME_INTERNAL;

typedef ULONG LOGICAL;
typedef ULONG* PLOGICAL;

typedef struct _WNF_STATE_NAME 
{
    ULONG                             Data[ 2 ];
} WNF_STATE_NAME, * PWNF_STATE_NAME;

typedef const struct _WNF_STATE_NAME* PCWNF_STATE_NAME;

typedef struct _WNF_TYPE_ID 
{
    GUID                              TypeId;
} WNF_TYPE_ID, * PWNF_TYPE_ID;

typedef const WNF_TYPE_ID* PCWNF_TYPE_ID;

typedef ULONG WNF_CHANGE_STAMP, * PWNF_CHANGE_STAMP;

typedef struct _WNF_DELIVERY_DESCRIPTOR 
{
    ULONG64                           SubscriptionId;
    WNF_STATE_NAME                    StateName;
    WNF_CHANGE_STAMP                  ChangeStamp;
    ULONG                             StateDataSize;
    ULONG                             EventMask;
    WNF_TYPE_ID                       TypeId;
    ULONG                             StateDataOffset;
} WNF_DELIVERY_DESCRIPTOR, * PWNF_DELIVERY_DESCRIPTOR;

typedef struct _WNF_NODE_HEADER
{
    USHORT                            NodeTypeCode;
    USHORT                            NodeByteSize;
} WNF_NODE_HEADER, * PWNF_NODE_HEADER;

typedef struct _WNF_SUBSCRIPTION_TABLE 
{
    WNF_NODE_HEADER                   Header;
    SRWLOCK                           NamesTableLock;
    LIST_ENTRY                        NamesTableEntry;
    LIST_ENTRY                        SerializationGroupListHead;
    SRWLOCK                           SerializationGroupLock;
    DWORD                             Unknown1[ 2 ];
    DWORD                             SubscribedEventSet;
    DWORD                             Unknown2[ 2 ];
    PTP_TIMER                         Timer;
    ULONG64                           TimerDueTime;
} WNF_SUBSCRIPTION_TABLE, * PWNF_SUBSCRIPTION_TABLE;

#pragma warning(push)
#pragma warning(disable:4214)

typedef struct _RTL_BALANCED_NODE
{
    union 
    {
        struct _RTL_BALANCED_NODE* Children[ 2 ];
        struct 
        {
            struct _RTL_BALANCED_NODE* Left;
            struct _RTL_BALANCED_NODE* Right;
        };
    };

#define RTL_BALANCED_NODE_RESERVED_PARENT_MASK 3

    union 
    {
        UCHAR Red : 1;
        UCHAR Balance : 2;
        ULONG_PTR ParentValue;
    };

} RTL_BALANCED_NODE, * PRTL_BALANCED_NODE;

typedef struct _RTL_RB_TREE
{
    _RTL_BALANCED_NODE* Root;
    _RTL_BALANCED_NODE* Min;

} RTL_RB_TREE, * PRTL_RB_TREE;

#pragma warning(pop)

#define RTL_BALANCED_NODE_GET_PARENT_POINTER(Node) \
    ((PRTL_BALANCED_NODE)((Node)->ParentValue & \
                          ~RTL_BALANCED_NODE_RESERVED_PARENT_MASK))

typedef struct _WNF_SUBSCRIPTION_TABLE_W11
{
    WNF_NODE_HEADER                   Header;
    SRWLOCK                           NamesTableLock;
    RTL_RB_TREE                       NamesTableEntry;
    LIST_ENTRY                        SerializationGroupListHead;
    SRWLOCK                           SerializationGroupLock;
    DWORD                             Unknown1[ 2 ];
    DWORD                             SubscribedEventSet;
    DWORD                             Unknown2[ 2 ];
    PTP_TIMER                         Timer;
    ULONG64                           TimerDueTime;
} WNF_SUBSCRIPTION_TABLE_W11, * PWNF_SUBSCRIPTION_TABLE_W11;

typedef struct _WNF_NAME_SUBSCRIPTION_W11
{
    WNF_NODE_HEADER                   Header;
    ULONG64                           SubscriptionId;
    WNF_STATE_NAME_INTERNAL           StateName;
    WNF_CHANGE_STAMP                  CurrentChangeStamp;
    RTL_BALANCED_NODE                 NamesTableEntry;
    PWNF_TYPE_ID                      TypeId;
    SRWLOCK                           SubscriptionLock;
    LIST_ENTRY                        SubscriptionsListHead;
    ULONG                             NormalDeliverySubscriptions;
    ULONG                             NotificationTypeCount[ 5 ];
    PWNF_DELIVERY_DESCRIPTOR          RetryDescriptor;
    ULONG                             DeliveryState;
    ULONG64                           ReliableRetryTime;
} WNF_NAME_SUBSCRIPTION_W11, * PWNF_NAME_SUBSCRIPTION_W11;

typedef struct _WNF_NAME_SUBSCRIPTION 
{
    WNF_NODE_HEADER                   Header;
    ULONG64                           SubscriptionId;
    WNF_STATE_NAME_INTERNAL           StateName;
    WNF_CHANGE_STAMP                  CurrentChangeStamp;
    LIST_ENTRY                        NamesTableEntry;
    PWNF_TYPE_ID                      TypeId;
    SRWLOCK                           SubscriptionLock;
    LIST_ENTRY                        SubscriptionsListHead;
    ULONG                             NormalDeliverySubscriptions;
    ULONG                             NotificationTypeCount[ 5 ];
    PWNF_DELIVERY_DESCRIPTOR          RetryDescriptor;
    ULONG                             DeliveryState;
    ULONG64                           ReliableRetryTime;
} WNF_NAME_SUBSCRIPTION, * PWNF_NAME_SUBSCRIPTION;

typedef struct _WNF_SERIALIZATION_GROUP 
{
    WNF_NODE_HEADER                   Header;
    ULONG                             GroupId;
    LIST_ENTRY                        SerializationGroupList;
    ULONG64                           SerializationGroupValue;
    ULONG64                           SerializationGroupMemberCount;
} WNF_SERIALIZATION_GROUP, * PWNF_SERIALIZATION_GROUP;

typedef NTSTATUS( *PWNF_USER_CALLBACK ) (
    WNF_STATE_NAME                    StateName,
    WNF_CHANGE_STAMP                  ChangeStamp,
    PWNF_TYPE_ID                      TypeId,
    PVOID                             CallbackContext,
    PVOID                             Buffer,
    ULONG                             BufferSize );

typedef struct _WNF_USER_SUBSCRIPTION 
{
    WNF_NODE_HEADER                   Header;
    LIST_ENTRY                        SubscriptionsListEntry;
    PWNF_NAME_SUBSCRIPTION            NameSubscription;
    PWNF_USER_CALLBACK                Callback;
    PVOID                             CallbackContext;
    ULONG64                           SubProcessTag;
    ULONG                             CurrentChangeStamp;
    ULONG                             DeliveryOptions;
    ULONG                             SubscribedEventSet;
    PWNF_SERIALIZATION_GROUP          SerializationGroup;
    ULONG                             UserSubscriptionCount;
    ULONG64                           Unknown[ 10 ];
} WNF_USER_SUBSCRIPTION, * PWNF_USER_SUBSCRIPTION;

typedef struct _CT_CONTEXT {
    PTP_WORK                          WorkItem;
    PWNF_USER_SUBSCRIPTION            Subscription;
    HANDLE                            hEvent;
} CT_CONTEXT, * PCT_CONTEXT;