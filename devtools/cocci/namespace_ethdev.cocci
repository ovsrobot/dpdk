@rule1@
identifier I =~  "^(RTE_FC_|ETH_MQ_|ETH_RSS_|DEV_RX_|DEV_TX_|ETH_LINK_|RTE_RETA|
ETH_SPEED|RTE_TUNNEL|ETH_VLAN|ETH_4|ETH_8|ETH_16|ETH_32|ETH_64|RTE_FDIR|RTE_L2|
ETH_DCB|ETH_MIRROR|ETH_VMDQ|ETH_NUM|ETH_QINQ|rte_fdir)";
@@
I

@ script : python p@
I << rule1.I;
J;
@@
coccinelle .J="RTE_ETH_" + I[4:];
if I.isupper() == False:
	coccinelle .J="rte_eth_" + I[4:];

exception_matches = ["ETH_RSS_MODE","ETH_VLAN_FILTER_ANY","ETH_VLAN_FILTER_SPEC",
"ETH_VLAN_FILTER_CLASSIFY","ETH_RSS_UPDATE","RTE_FDIR_MODE"]

if any(x in I for x in exception_matches):
        coccinelle .J= I;

@ identifier@
identifier rule1.I;
identifier p.J;
@@
- I
+ J

@rule2@
identifier A  =~  "^(RTE_FC_|ETH_MQ_|ETH_RSS_|DEV_RX_|DEV_TX_|ETH_LINK_|RTE_RETA|
ETH_SPEED|RTE_TUNNEL|ETH_VLAN|ETH_4|ETH_8|ETH_16|ETH_32|ETH_64|RTE_FDIR|RTE_L2|
ETH_DCB|ETH_MIRROR|ETH_VMDQ|ETH_NUM|ETH_QINQ)";
expression B ;
@@
#define A B

@ script : python p2@
A << rule2.A;
K;
@@
coccinelle .K="RTE_ETH_" + A[4:];

@ identifier2@
identifier rule2.A;
expression rule2.B;
identifier p2.K;
@@
- #define A B
+ #define K B
+ #define A K
