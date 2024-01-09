from pathlib import Path

from Crypto.Hash import SHA512
from pyteal import *
from pyteal.ast.expr import Expr
from pyteal.ir import TealSimpleBlock

version = "v0.5.0"

################################################################################
# Constants
################################################################################


HI4GE = Addr("HI4GEV4ZU32TGWUPKC5FKNCK6DZOLX2RRX4BVB3QG6WUHQ2UAS4GM3CN5U")
LAUNCH = Addr("LAUNCHPHD5NWWTDNVHOCFORJRFQYSY7UJWRF6A35LYMIDG4QHSHLGTMIEY")

BOOL_FALSE = Bytes("base16", "0x00")
BOOL_TRUE = Bytes("base16", "0x80")

BYTES_ONE = Bytes("base16", "0x01")
BYTES_ZERO = Bytes("base16", "0x00")

EVENT_APPROVAL = "arc72_Approval(address,address,uint256)"
EVENT_APPROVAL_FOR_ALL = "arc72_ApprovalForAll(address,address,bool)"
EVENT_MINT = "highforge_Mint(address,uint256,uint64,uint64,uint64)"
EVENT_REVEAL = "highforge_Reveal(uint256,byte[256])"
EVENT_TRANSFER = "arc72_Transfer(address,address,uint256)"
EVENT_UPDATE_URI = "highforge_UpdateURI(uint256,byte[256])"

INTERFACE_ARC72_CORE = Bytes("base16", "0x53f02a40")
INTERFACE_ARC72_ENUMERATION = Bytes("base16", "0xa57d4679")
INTERFACE_ARC72_MANAGEMENT = Bytes("base16", "0xb9c6f696")
INTERFACE_ARC72_METADATA = Bytes("base16", "0xc3c1fc00")
INTERFACE_MASK = Bytes("base16", "0xffffffff")
INTERFACE_SUPPORTS_INTERFACE = Bytes("base16", "0x4e22a3ba")

PREFIX_RETURN = Bytes("base16", "0x151f7c75")

LENGTH_ADDRESS = Int(32)
LENGTH_BALANCE_BOX = Int(32)
LENGTH_BOOL = Int(1)
LENGTH_INDEX_BOX = Int(32)
LENGTH_METADATA_URI = Int(256)
LENGTH_NFT_BOX = Int(320)
LENGTH_UINT256 = Int(32)
LENGTH_UINT64 = Int(8)
LENGTH_UINT8 = Int(1)

MIN_BALANCE_APPROVAL_BOX = Int(2500 + (((2 * 32) + 1) * 400))
MIN_BALANCE_INDEX_BOX = Int(2500 + (((1 + 32) + 32) * 400))
MIN_BALANCE_NFT_BOX = Int(2500 + (((1 + 32) + 320) * 400))
MIN_BALANCE_BALANCE_BOX = Int(2500 + (((1 + 32) + 32) * 400))

LAUNCH_FEES = Global.min_txn_fee()

################################################################################
# Helper Functions
################################################################################


class ABI_Method:
    def __init__(self, abi, handler):
        self._abi = abi
        self._handler = handler

        self._signature = (
            abi["name"]
            + "("
            + ",".join([arg["type"] for arg in abi["args"]])
            + ")"
            + abi["returns"]["type"]
        )
        self.selector = abi_method(self._signature)

        print(abi["name"], self.selector)

    def handler(self):
        args = {}
        commands = []

        length_map = {
            "account": LENGTH_UINT8,
            "address": LENGTH_ADDRESS,
            "asset": LENGTH_UINT8,
            "bool": LENGTH_BOOL,
            "byte[4]": Int(4),
            "byte[256]": Int(256),
            "uint256": LENGTH_UINT256,
            "uint64": LENGTH_UINT64,
        }

        for i, arg in enumerate(self._abi["args"]):
            args[arg["name"]] = ScratchVar(
                TealType.uint64 if arg["type"] == "asset" else TealType.bytes
            )

            commands.append(
                Assert(Len(Txn.application_args[i + 1]) == length_map[arg["type"]])
            )
            commands.append(
                args[arg["name"]].store(
                    Txn.accounts[Btoi(Txn.application_args[i + 1])]
                    if arg["type"] == "account"
                    else (
                        Txn.assets[Btoi(Txn.application_args[i + 1])]
                        if arg["type"] == "asset"
                        else Txn.application_args[i + 1]
                    )
                )
            )

        return Seq(
            *commands,
            self._handler(args),
        )


class EmptyExpr(Expr):
    def __str__(self):
        return ""

    def __teal__(self, _):
        start = TealSimpleBlock([])
        end = start
        return start, end

    def has_return(self):
        return False

    def type_of(self):
        return TealType.none


class NFT(EmptyExpr):
    # NFT Box Structure
    # owner - 32 bytes
    # operator - 32 bytes
    # metadata_uri - 256 bytes
    box_length = LENGTH_NFT_BOX

    field_indices = {
        "owner": Int(0),
        "operator": Int(32),
        "metadata_uri": Int(64),
    }

    field_lengths = {
        "owner": LENGTH_ADDRESS,
        "operator": LENGTH_ADDRESS,
        "metadata_uri": LENGTH_METADATA_URI,
    }

    def __init__(self, token_id):
        self.box_name = Concat(Bytes("n"), token_id)
        self.token_id = token_id

    def _emit(self, event, bytes):
        return abi_event(event, bytes)

    def approve(self, operator):
        return Seq(
            self.set("operator", operator),
            self.emit_approval(self.get("owner"), operator),
        )

    def burn(self):
        owner = ScratchVar(TealType.bytes)

        return Seq(
            owner.store(self.get("owner")),
            self.transfer(owner.load(), Global.zero_address()),
            Assert(App.box_delete(self.box_name)),
            send_algo(MIN_BALANCE_NFT_BOX, owner.load()),
        )

    def create(self, owner):
        return Seq(
            # create the NFT
            Assert(Not(self.exists())),
            Assert(App.box_create(self.box_name, self.box_length)),
            self.transfer(Global.zero_address(), owner),
        )

    def emit_approval(self, owner, approved):
        return self._emit(EVENT_APPROVAL, Concat(owner, approved, self.token_id))

    def emit_transfer(self, from_, to):
        return self._emit(
            EVENT_TRANSFER,
            Concat(
                from_,
                to,
                self.token_id,
            ),
        )

    def exists(self):
        return Seq(length := App.box_length(self.box_name), length.hasValue())

    def get(self, key):
        return App.box_extract(
            self.box_name, self.field_indices[key], self.field_lengths[key]
        )

    def is_revealed(self):
        return self.get("metadata_uri") != BytesZero(LENGTH_METADATA_URI)

    def set(self, key, value):
        return Seq(
            Assert(Len(value) == self.field_lengths[key]),
            App.box_replace(self.box_name, self.field_indices[key], value),
        )

    def transfer(self, from_, to):
        return Seq(
            self.set("owner", to),
            self.set("operator", Global.zero_address()),
            If(
                from_ != Global.zero_address(),
                Seq(
                    contents := App.box_get(Concat(Bytes("b"), from_)),
                    Assert(contents.hasValue()),
                    App.box_put(
                        Concat(Bytes("b"), from_),
                        Btou256(BytesMinus(contents.value(), BYTES_ONE)),
                    ),
                ),
            ),
            Seq(
                contents := App.box_get(Concat(Bytes("b"), to)),
                App.box_put(
                    Concat(Bytes("b"), to),
                    Btou256(
                        BytesAdd(
                            If(contents.hasValue(), contents.value(), BYTES_ZERO),
                            BYTES_ONE,
                        )
                    ),
                ),
            ),
            self.emit_transfer(from_, to),
        )


def Btou256(bytes):
    return Concat(BytesZero(LENGTH_UINT256 - Len(bytes)), bytes)


def Itou256(int):
    return Concat(BytesZero(LENGTH_UINT256 - LENGTH_UINT64), Itob(int))


def U256toi(bytes):
    return Btoi(Extract(bytes, LENGTH_UINT256 - LENGTH_UINT64, LENGTH_UINT64))


def abi_event(signature, bytes):
    return Log(Concat(abi_method(signature), bytes))


def abi_method(signature):
    hash = SHA512.new(truncate="256")
    hash.update(signature.encode("utf-8"))
    selector = hash.hexdigest()[0:8]
    return Bytes("base16", "0x" + selector)


def abi_return(bytes=None):
    return (
        Seq(
            Log(Concat(PREFIX_RETURN, bytes)),
            Approve(),
        )
        if bytes is not None
        else Approve()
    )


def assert_is_creator():
    return Assert(Txn.sender() == Global.creator_address())


def assert_is_launch():
    return Assert(Txn.sender() == LAUNCH)


@Subroutine(TealType.none)
def assert_mint_funding(index):
    return Assert(
        is_algo_txn(
            index,
            MIN_BALANCE_NFT_BOX  # for NFT storage
            + MIN_BALANCE_INDEX_BOX  # for NFT lookup by index
            + LAUNCH_FEES,  # to pay for LAUNCH's txn fees
            Global.current_application_address(),
        )
    )


@Subroutine(TealType.none)
def build_send_asset(assetID, amount, receiver):
    return Seq(
        InnerTxnBuilder.Begin(),
        InnerTxnBuilder.SetField(TxnField.type_enum, TxnType.AssetTransfer),
        InnerTxnBuilder.SetField(TxnField.fee, Int(0)),
        InnerTxnBuilder.SetField(TxnField.xfer_asset, assetID),
        InnerTxnBuilder.SetField(TxnField.asset_amount, amount),
        InnerTxnBuilder.SetField(TxnField.asset_receiver, receiver),
    )


def closeout_algo(receiver):
    return Seq(
        InnerTxnBuilder.Begin(),
        InnerTxnBuilder.SetField(TxnField.type_enum, TxnType.Payment),
        InnerTxnBuilder.SetField(TxnField.fee, Int(0)),
        InnerTxnBuilder.SetField(TxnField.amount, Int(0)),
        InnerTxnBuilder.SetField(TxnField.close_remainder_to, receiver),
        InnerTxnBuilder.SetField(TxnField.receiver, receiver),
        InnerTxnBuilder.Submit(),
    )


@Subroutine(TealType.none)
def closeout_asset_to_creator(assetID):
    assetCreator = AssetParam.creator(assetID)

    return Seq(
        assetCreator,
        build_send_asset(assetID, Int(0), assetCreator.value()),
        InnerTxnBuilder.SetField(TxnField.asset_close_to, assetCreator.value()),
        InnerTxnBuilder.Submit(),
    )


def closeout_asset(assetID, receiver):
    return Seq(
        build_send_asset(assetID, Int(0), receiver),
        InnerTxnBuilder.SetField(TxnField.asset_close_to, receiver),
        InnerTxnBuilder.Submit(),
    )


def create_asset(assetName, unitName, total, assetURL, hash, manager, reserve):
    return Seq(
        InnerTxnBuilder.Begin(),
        InnerTxnBuilder.SetField(TxnField.type_enum, TxnType.AssetConfig),
        InnerTxnBuilder.SetField(TxnField.fee, Int(0)),
        InnerTxnBuilder.SetField(TxnField.config_asset_total, total),
        InnerTxnBuilder.SetField(TxnField.config_asset_decimals, Int(0)),
        InnerTxnBuilder.SetField(TxnField.config_asset_name, assetName),
        InnerTxnBuilder.SetField(
            TxnField.config_asset_unit_name,
            unitName,
        ),
        InnerTxnBuilder.SetField(TxnField.config_asset_url, assetURL),
        InnerTxnBuilder.SetField(TxnField.config_asset_metadata_hash, hash),
        InnerTxnBuilder.SetField(TxnField.config_asset_manager, manager),
        InnerTxnBuilder.SetField(TxnField.config_asset_reserve, reserve),
        InnerTxnBuilder.Submit(),
    )


def distribute_payments(assetID, total):
    artistAmount = ScratchVar(TealType.uint64)
    charityAmount = ScratchVar(TealType.uint64)
    launchpadAmount = ScratchVar(TealType.uint64)

    return Seq(
        # figure out how much charity gets
        charityAmount.store(
            If(
                And(
                    App.globalGet(Bytes("charityAddress"))
                    != Global.current_application_address(),
                    App.globalGet(Bytes("charityPoints")) > Int(0),
                ),
                get_cut(total, App.globalGet(Bytes("charityPoints"))),
                Int(0),
            )
        ),
        # figure out how much the launchpad gets
        launchpadAmount.store(get_cut(total, App.globalGet(Bytes("launchpadFee")))),
        artistAmount.store(total - launchpadAmount.load()),
        If(
            assetID == Int(0),
            Seq(
                # only payout to charity if it doesn't cause any errors
                If(
                    And(
                        charityAmount.load(),
                        artistAmount.load() >= charityAmount.load(),
                        Or(
                            charityAmount.load() >= Global.min_balance(),
                            Balance(App.globalGet(Bytes("charityAddress")))
                            >= Global.min_balance(),
                        ),
                    ),
                    Seq(
                        artistAmount.store(artistAmount.load() - charityAmount.load()),
                        send_algo(
                            charityAmount.load(), App.globalGet(Bytes("charityAddress"))
                        ),
                    ),
                ),
                send_algo(artistAmount.load(), Global.creator_address()),
                send_algo(launchpadAmount.load(), HI4GE),
            ),
            Seq(
                # only payout to charity if it doesn't cause any errors
                If(
                    And(
                        charityAmount.load(),
                        artistAmount.load() >= charityAmount.load(),
                        Seq(
                            opted_in := AssetHolding.balance(
                                App.globalGet(Bytes("charityAddress")),
                                assetID,
                            ),
                            opted_in.hasValue(),
                        ),
                    ),
                    Seq(
                        artistAmount.store(artistAmount.load() - charityAmount.load()),
                        send_asset(
                            assetID,
                            charityAmount.load(),
                            App.globalGet(Bytes("charityAddress")),
                        ),
                    ),
                ),
                send_asset(
                    assetID,
                    artistAmount.load(),
                    Global.creator_address(),
                ),
                send_asset(assetID, launchpadAmount.load(), HI4GE),
            ),
        ),
    )


@Subroutine(TealType.uint64)
def get_cut(total, points):
    return Btoi(BytesDiv(BytesMul(Itob(total), Itob(points)), Itob(Int(10000))))


@Subroutine(TealType.uint64)
def is_algo_txn(index, amount, receiver):
    return And(
        Gtxn[index].type_enum() == TxnType.Payment,
        Gtxn[index].close_remainder_to() == Global.zero_address(),
        Gtxn[index].rekey_to() == Global.zero_address(),
        Gtxn[index].amount() == amount,
        Gtxn[index].receiver() == receiver,
    )


@Subroutine(TealType.uint64)
def is_asset_txn(index, assetID, amount, receiver):
    return And(
        Gtxn[index].type_enum() == TxnType.AssetTransfer,
        Gtxn[index].asset_close_to() == Global.zero_address(),
        Gtxn[index].rekey_to() == Global.zero_address(),
        Gtxn[index].xfer_asset() == assetID,
        Gtxn[index].asset_amount() == amount,
        Gtxn[index].asset_receiver() == receiver,
    )


def is_noop_txn(index, appID, method):
    return And(
        Gtxn[index].type_enum() == TxnType.ApplicationCall,
        Gtxn[index].rekey_to() == Global.zero_address(),
        Gtxn[index].application_id() == appID,
        Gtxn[index].on_completion() == OnComplete.NoOp,
        Gtxn[index].application_args[0] == method,
    )


@Subroutine(TealType.bytes)
def nibble_to_ascii(nibble):
    return Extract(
        Itob(If(nibble < Int(10), Int(48) + nibble, Int(87) + nibble)), Int(7), Int(1)
    )


def optin_asset(assetID):
    return Seq(
        build_send_asset(assetID, Int(0), Global.current_application_address()),
        InnerTxnBuilder.Submit(),
    )


@Subroutine(TealType.none)
def send_algo(amount, receiver):
    return Seq(
        InnerTxnBuilder.Begin(),
        InnerTxnBuilder.SetField(TxnField.type_enum, TxnType.Payment),
        InnerTxnBuilder.SetField(TxnField.fee, Int(0)),
        InnerTxnBuilder.SetField(TxnField.amount, amount),
        InnerTxnBuilder.SetField(TxnField.receiver, receiver),
        InnerTxnBuilder.Submit(),
    )


@Subroutine(TealType.none)
def send_algo_cover_fee(amount, receiver):
    return If(
        And(
            amount > Global.min_txn_fee(),
            Balance(receiver) + amount - Global.min_txn_fee() >= Global.min_balance(),
        ),
        Seq(
            InnerTxnBuilder.Begin(),
            InnerTxnBuilder.SetField(TxnField.type_enum, TxnType.Payment),
            InnerTxnBuilder.SetField(TxnField.amount, amount - Global.min_txn_fee()),
            InnerTxnBuilder.SetField(TxnField.fee, Global.min_txn_fee()),
            InnerTxnBuilder.SetField(TxnField.receiver, receiver),
            InnerTxnBuilder.Submit(),
        ),
    )


def send_asset(assetID, amount, receiver):
    return Seq(build_send_asset(assetID, amount, receiver), InnerTxnBuilder.Submit())


def sha_to_token_id(sha256):
    byte = ScratchVar(TealType.uint64)
    i = ScratchVar(TealType.uint64)
    value = ScratchVar(TealType.bytes)

    # todo:
    # for each byte,
    # mod it by 10
    # convert that to ascii
    # should be 32 bytes long
    return Seq(
        value.store(Bytes("")),
        i.store(Int(0)),
        While(i.load() < Int(16)).Do(
            Seq(
                byte.store(GetByte(sha256, i.load())),
                value.store(
                    Concat(
                        value.load(),
                        nibble_to_ascii(byte.load() / Int(16)),
                        nibble_to_ascii(byte.load() & Int(15)),
                    )
                ),
                i.store(i.load() + Int(1)),
            )
        ),
        value.load(),
    )


################################################################################
# NoOp Branches
################################################################################


def on_claim_algo():
    claimableAlgo = Balance(Global.current_application_address()) - MinBalance(
        Global.current_application_address()
    )

    return Seq(
        assert_is_creator(),
        send_algo(claimableAlgo, Global.creator_address()),
        Approve(),
    )


def on_claim_asset(assetID):
    amount = AssetHolding.balance(Global.current_application_address(), assetID)

    return Seq(
        assert_is_creator(),
        amount,
        send_asset(
            assetID,
            amount.value(),
            Global.creator_address(),
        ),
        Approve(),
    )


def on_claim_wl_alt():
    return on_claim_asset(App.globalGet(Bytes("wlAltID")))


def on_claim_wl_token():
    return on_claim_asset(App.globalGet(Bytes("wlTokenID")))


def on_disable_whitelist():
    return Seq(
        assert_is_creator(),
        If(
            App.globalGet(Bytes("wlAltID")),
            closeout_asset_to_creator(App.globalGet(Bytes("wlAltID"))),
        ),
        App.globalPut(Bytes("wlLaunchStart"), Int(0)),
        App.globalPut(Bytes("wlTokenID"), Int(0)),
        App.globalPut(Bytes("wlPrice"), Int(0)),
        App.globalPut(Bytes("wlAltID"), Int(0)),
        App.globalPut(Bytes("wlAltPrice"), Int(0)),
        Approve(),
    )


def on_enable_whitelist():
    hash = ScratchVar(TealType.bytes)
    i = ScratchVar(TealType.uint64)
    name = ScratchVar(TealType.bytes)

    return Seq(
        assert_is_creator(),
        Assert(Btoi(Txn.application_args[1]) < App.globalGet(Bytes("launchStart"))),
        App.globalPut(Bytes("wlLaunchStart"), Btoi(Txn.application_args[1])),
        App.globalPut(Bytes("wlPrice"), Btoi(Txn.application_args[2])),
        App.globalPut(Bytes("wlAltID"), Btoi(Txn.application_args[3])),
        App.globalPut(Bytes("wlAltPrice"), Btoi(Txn.application_args[4])),
        App.globalPut(Bytes("wlMax"), Btoi(Txn.application_args[5])),
        hash.store(Sha256(Itob(Global.current_application_id()))),
        name.store(Bytes("High Forge EA Token: 12345678901")),
        For(i.store(Int(0)), i.load() < Int(11), i.store(i.load() + Int(1))).Do(
            name.store(
                SetByte(
                    name.load(),
                    i.load() + Int(21),
                    (GetByte(hash.load(), i.load()) % Int(26)) + Int(65),
                ),
            )
        ),
        create_asset(
            name.load(),
            Bytes("EARLY"),
            App.globalGet(Bytes("maxSupply")) * Int(10),
            Bytes("https://highforge.io"),
            Global.zero_address(),
            Global.current_application_address(),
            Global.current_application_address(),
        ),
        App.globalPut(Bytes("wlTokenID"), InnerTxn.created_asset_id()),
        If(
            App.globalGet(Bytes("wlAltID")),
            optin_asset(App.globalGet(Bytes("wlAltID"))),
        ),
        Approve(),
    )


def on_set_charity():
    return Seq(
        assert_is_creator(),
        App.globalPut(Bytes("charityAddress"), Txn.application_args[1]),
        App.globalPut(Bytes("charityPoints"), Btoi(Txn.application_args[2])),
        Approve(),
    )


def on_set_launch_dates():
    return Seq(
        assert_is_creator(),
        App.globalPut(Bytes("launchStart"), Btoi(Txn.application_args[1])),
        If(
            Txn.application_args.length() == Int(3),
            Seq(
                Assert(App.globalGet(Bytes("wlTokenID"))),
                Assert(Btoi(Txn.application_args[2]) < Btoi(Txn.application_args[1])),
                App.globalPut(Bytes("wlLaunchStart"), Btoi(Txn.application_args[2])),
            ),
        ),
        Approve(),
    )


def on_set_launch_details():
    return Seq(
        assert_is_creator(),
        App.globalPut(Bytes("price"), Btoi(Txn.application_args[1])),
        App.globalPut(Bytes("maxSupply"), Btoi(Txn.application_args[2])),
        App.globalPut(Bytes("launchStart"), Btoi(Txn.application_args[3])),
        App.globalPut(Bytes("launchEnd"), Int(0)),  # for now, don't allow end date
        # App.globalPut(Bytes("launchEnd"), Btoi(Txn.application_args[4])),
        Approve(),
    )


def on_set_launch_paused():
    return Seq(
        assert_is_creator(),
        App.globalPut(Bytes("launchPaused"), Btoi(Txn.application_args[1])),
        Approve(),
    )


def on_set_launchpad_fee():
    return Seq(
        assert_is_launch(),
        App.globalPut(Bytes("launchpadFee"), Btoi(Txn.application_args[1])),
        Approve(),
    )


def approveHandler(args):
    return Seq(
        nft := NFT(args["tokenId"].load()),
        Assert(nft.exists()),
        Assert(Txn.sender() == nft.get("owner")),
        nft.approve(args["approved"].load()),
        abi_return(),
    )


approve = ABI_Method(
    {
        "name": "arc72_approve",
        "desc": "Approve a controller for a single NFT",
        "readonly": False,
        "args": [
            {
                "type": "address",
                "name": "approved",
                "desc": "Approved controller address",
            },
            {"type": "uint256", "name": "tokenId", "desc": "The ID of the NFT"},
        ],
        "returns": {"type": "void"},
    },
    approveHandler,
)


def balanceOfHandler(args):
    return Seq(
        contents := App.box_get(Concat(Bytes("b"), args["owner"].load())),
        abi_return(
            If(contents.hasValue(), contents.value(), BytesZero(LENGTH_UINT256))
        ),
    )


balanceOf = ABI_Method(
    {
        "name": "arc72_balanceOf",
        "desc": "Returns the number of NFTs owned by an address",
        "readonly": True,
        "args": [
            {"type": "address", "name": "owner"},
        ],
        "returns": {"type": "uint256"},
    },
    balanceOfHandler,
)


def burnHandler(args):
    return Seq(
        nft := NFT(args["tokenId"].load()),
        Assert(nft.exists()),
        Assert(Txn.sender() == nft.get("owner")),
        nft.burn(),
        abi_return(),
    )


burn = ABI_Method(
    {
        "name": "burn",
        "desc": "Burns the specified NFT",
        "readonly": False,
        "args": [
            {"type": "uint256", "name": "tokenId", "desc": "The ID of the NFT"},
        ],
        "returns": {"type": "void"},
    },
    burnHandler,
)


def getApprovedHandler(args):
    return Seq(
        nft := NFT(args["tokenId"].load()),
        Assert(nft.exists()),
        abi_return(nft.get("operator")),
    )


getApproved = ABI_Method(
    {
        "name": "arc72_getApproved",
        "desc": "Get the current approved address for a single NFT",
        "readonly": True,
        "args": [
            {"type": "uint256", "name": "tokenId", "desc": "The ID of the NFT"},
        ],
        "returns": {"type": "address", "desc": "address of approved user or zero"},
    },
    getApprovedHandler,
)


def isApprovedForAllHandler(args):
    return Seq(
        isOperator := App.box_length(
            Concat(args["owner"].load(), args["operator"].load())
        ),
        abi_return(Itob(isOperator.hasValue())),
    )


isApprovedForAll = ABI_Method(
    {
        "name": "arc72_isApprovedForAll",
        "desc": "Query if an address is an authorized operator for another address",
        "readonly": True,
        "args": [
            {"type": "address", "name": "owner"},
            {"type": "address", "name": "operator"},
        ],
        "returns": {
            "type": "bool",
            "desc": "whether operator is authorized for all NFTs of owner",
        },
    },
    isApprovedForAllHandler,
)


def mintHandler(args):
    assetID = ScratchVar(TealType.uint64)
    paidAmount = ScratchVar(TealType.uint64)
    receiptBox = ScratchVar(TealType.bytes)
    receiptContent = ScratchVar(TealType.bytes)

    return Seq(
        # make sure the max supply has not been reached
        Assert(App.globalGet(Bytes("totalMinted")) < App.globalGet(Bytes("maxSupply"))),
        If(
            # if creator is calling, ignore price, period, and paused status
            Txn.sender() == Global.creator_address(),
            Seq(
                assetID.store(Int(0)),
                paidAmount.store(Int(0)),
                assert_mint_funding(Txn.group_index() - Int(1)),
            ),
            Seq(
                # make sure the launch is not paused
                Assert(App.globalGet(Bytes("launchPaused")) == Int(0)),
                # make sure the mint is not over. launchEnd == 0 means it never ends
                Assert(
                    Or(
                        App.globalGet(Bytes("launchEnd")) == Int(0),
                        Global.latest_timestamp() < App.globalGet(Bytes("launchEnd")),
                    )
                ),
                If(
                    # if the time is after the launch start, it's a normal mint
                    Global.latest_timestamp() >= App.globalGet(Bytes("launchStart")),
                    Seq(
                        # make sure they pay the mint price
                        If(
                            is_algo_txn(
                                Txn.group_index() - Int(1),
                                App.globalGet(Bytes("price")),
                                Global.current_application_address(),
                            ),
                            Seq(
                                assetID.store(Int(0)),
                                paidAmount.store(App.globalGet(Bytes("price"))),
                            ),
                            Reject(),
                        ),
                        assert_mint_funding(Txn.group_index() - Int(2)),
                    ),
                    Seq(
                        # make sure whitelist is enabled
                        Assert(App.globalGet(Bytes("wlTokenID"))),
                        # make sure we are in the whitelist window
                        Assert(
                            Global.latest_timestamp()
                            >= App.globalGet(Bytes("wlLaunchStart"))
                        ),
                        # make sure white list is not maxed out
                        Assert(
                            Or(
                                # wlMax == 0 means no limit
                                App.globalGet(Bytes("wlMax")) == Int(0),
                                App.globalGet(Bytes("wlMinted"))
                                < App.globalGet(Bytes("wlMax")),
                            )
                        ),
                        # make sure they pay the whitelist token
                        Assert(
                            is_asset_txn(
                                Txn.group_index() - Int(2),
                                App.globalGet(Bytes("wlTokenID")),
                                Int(1),
                                Global.current_application_address(),
                            )
                        ),
                        # make sure they pay the mint price
                        If(
                            is_algo_txn(
                                Txn.group_index() - Int(1),
                                App.globalGet(Bytes("wlPrice")),
                                Global.current_application_address(),
                            ),
                            Seq(
                                assetID.store(Int(0)),
                                paidAmount.store(App.globalGet(Bytes("wlPrice"))),
                            ),
                            If(
                                And(
                                    App.globalGet(Bytes("wlAltID")),
                                    is_asset_txn(
                                        Txn.group_index() - Int(1),
                                        App.globalGet(Bytes("wlAltID")),
                                        App.globalGet(Bytes("wlAltPrice")),
                                        Global.current_application_address(),
                                    ),
                                ),
                                Seq(
                                    assetID.store(App.globalGet(Bytes("wlAltID"))),
                                    paidAmount.store(
                                        App.globalGet(Bytes("wlAltPrice"))
                                    ),
                                ),
                                Reject(),
                            ),
                        ),
                        assert_mint_funding(Txn.group_index() - Int(3)),
                        App.globalPut(
                            Bytes("wlMinted"), App.globalGet(Bytes("wlMinted")) + Int(1)
                        ),
                    ),
                ),
            ),
        ),
        # send out everyone's cuts
        distribute_payments(assetID.load(), paidAmount.load()),
        # send algo to cover the revealing of the NFT
        send_algo(LAUNCH_FEES, LAUNCH),
        # create the receipt box and make sure it doesn't already exist
        receiptBox.store(Concat(Bytes("r"), args["tempTokenId"].load())),
        length := App.box_length(receiptBox.load()),
        Assert(Not(length.hasValue())),
        # we make the receipt box the same size as an NFT box
        # that way the user covers the min-balance cost
        # and during the reveal we can just replace the receipt box with the NFT box
        Assert(App.box_create(receiptBox.load(), LENGTH_NFT_BOX)),
        Assert(
            App.box_create(
                Concat(Bytes("t"), args["tempTokenId"].load()), LENGTH_INDEX_BOX
            )
        ),
        receiptContent.store(
            Concat(
                Txn.sender(),
                Itou256(App.globalGet(Bytes("nextMintID"))),
                Itob(assetID.load()),
                Itob(paidAmount.load()),
                Itob(Global.latest_timestamp()),
            )
        ),
        App.box_replace(
            receiptBox.load(),
            Int(0),
            receiptContent.load(),
        ),
        # emit the mint event
        abi_event(EVENT_MINT, receiptContent.load()),
        # update variables for next mint
        App.globalPut(Bytes("nextMintID"), App.globalGet(Bytes("nextMintID")) + Int(1)),
        App.globalPut(
            Bytes("totalMinted"), App.globalGet(Bytes("totalMinted")) + Int(1)
        ),
        abi_return(Itou256(App.globalGet(Bytes("nextMintID")) - Int(1))),
    )


mint = ABI_Method(
    {
        "name": "highforge_mint",
        "desc": "Attempts to mint an NFT for the user",
        "readonly": False,
        "args": [
            {
                "type": "uint256",
                "name": "tempTokenId",
                "desc": "A unique temporary token ID for the NFT",
            },
        ],
        "returns": {
            "type": "uint256",
            "desc": "tokenId - The ID of the NFT that was minted",
        },
    },
    mintHandler,
)


def ownerOfHandler(args):
    nft = NFT(args["tokenId"].load())

    return abi_return(
        If(
            nft.exists(),
            nft.get("owner"),
            Global.zero_address(),
        )
    )


ownerOf = ABI_Method(
    {
        "name": "arc72_ownerOf",
        "desc": "Returns the address of the current owner of the NFT with the given tokenId",
        "readonly": True,
        "args": [
            {"type": "uint256", "name": "tokenId", "desc": "The ID of the NFT"},
        ],
        "returns": {"type": "address", "desc": "The current owner of the NFT."},
    },
    ownerOfHandler,
)


def revealHandler(args):
    receiptBox = ScratchVar(TealType.bytes)
    sender = ScratchVar(TealType.bytes)
    tokenId = ScratchVar(TealType.bytes)
    collectionIndex = ScratchVar(TealType.bytes)

    return Seq(
        assert_is_launch(),
        # load the receipt
        receiptBox.store(Concat(Bytes("r"), args["tempTokenId"].load())),
        length := App.box_length(receiptBox.load()),
        Assert(length.hasValue()),
        sender.store(App.box_extract(receiptBox.load(), Int(0), LENGTH_ADDRESS)),
        tokenId.store(
            App.box_extract(receiptBox.load(), LENGTH_ADDRESS, LENGTH_UINT256)
        ),
        # verify against the receipt
        Assert(args["tokenId"].load() == tokenId.load()),
        # delete the receipt box
        Assert(App.box_delete(receiptBox.load())),
        Assert(App.box_delete(Concat(Bytes("t"), args["tempTokenId"].load()))),
        # create the NFT
        nft := NFT(args["tokenId"].load()),
        nft.create(sender.load()),
        nft.set("metadata_uri", args["tokenURI"].load()),
        # create the index lookup box
        collectionIndex.store(
            Itou256(U256toi(args["tokenId"].load()) - Int(1)),
        ),
        length := App.box_length(Concat(Bytes("i"), collectionIndex.load())),
        Assert(Not(length.hasValue())),
        App.box_put(Concat(Bytes("i"), collectionIndex.load()), args["tokenId"].load()),
        # emit event and return
        abi_event(
            EVENT_REVEAL, Concat(args["tokenId"].load(), args["tokenURI"].load())
        ),
        abi_return(),
    )


reveal = ABI_Method(
    {
        "name": "highforge_reveal",
        "desc": "Reveals the NFT",
        "readonly": False,
        "args": [
            {
                "type": "uint256",
                "name": "tempTokenId",
                "desc": "The temporary token ID",
            },
            {
                "type": "uint256",
                "name": "tokenId",
                "desc": "The actual token ID",
            },
            {
                "type": "byte[256]",
                "name": "tokenURI",
                "desc": "The metadata URI for the token",
            },
        ],
        "returns": {"type": "void"},
    },
    revealHandler,
)


def setApprovalForAllHandler(args):
    return Seq(
        If(
            args["approved"].load() == BOOL_TRUE,
            Assert(
                App.box_create(Concat(Txn.sender(), args["operator"].load()), Int(1))
            ),
            If(
                args["approved"].load() == BOOL_FALSE,
                Assert(App.box_delete(Concat(Txn.sender(), args["operator"].load()))),
                Reject(),
            ),
        ),
        abi_event(
            EVENT_APPROVAL_FOR_ALL,
            Concat(
                Txn.sender(),
                args["operator"].load(),
                args["approved"].load(),
            ),
        ),
        abi_return(),
    )


setApprovalForAll = ABI_Method(
    {
        "name": "arc72_setApprovalForAll",
        "desc": "Approve an operator for all NFTs for a user",
        "readonly": False,
        "args": [
            {
                "type": "address",
                "name": "operator",
                "desc": "Approved operator address",
            },
            {
                "type": "bool",
                "name": "approved",
                "desc": "true to give approval, false to revoke",
            },
        ],
        "returns": {"type": "void"},
    },
    setApprovalForAllHandler,
)


def setupBalanceHandler(args):
    return Seq(
        Assert(
            is_algo_txn(
                Txn.group_index() - Int(1),
                MIN_BALANCE_BALANCE_BOX,
                Global.current_application_address(),
            )
        ),
        length := App.box_length(Concat(Bytes("b"), Txn.sender())),
        If(
            length.hasValue(),
            send_algo_cover_fee(
                MIN_BALANCE_BALANCE_BOX,
                Gtxn[Txn.group_index() - Int(1)].sender(),
            ),
            Assert(
                App.box_create(Concat(Bytes("b"), Txn.sender()), LENGTH_BALANCE_BOX)
            ),
        ),
        abi_return(),
    )


setupBalance = ABI_Method(
    {
        "name": "highforge_setupBalance",
        "desc": "Makes sure that the balance box for the sender is set up",
        "readonly": False,
        "args": [],
        "returns": {"type": "void"},
    },
    setupBalanceHandler,
)


def supportsInterfaceHandler(args):
    return Seq(
        If(
            args["interfaceID"].load() == INTERFACE_SUPPORTS_INTERFACE,
            abi_return(BOOL_TRUE),
        ),
        If(args["interfaceID"].load() == INTERFACE_MASK, abi_return(BOOL_FALSE)),
        If(args["interfaceID"].load() == INTERFACE_ARC72_CORE, abi_return(BOOL_TRUE)),
        If(
            args["interfaceID"].load() == INTERFACE_ARC72_ENUMERATION,
            abi_return(BOOL_TRUE),
        ),
        If(
            args["interfaceID"].load() == INTERFACE_ARC72_MANAGEMENT,
            abi_return(BOOL_TRUE),
        ),
        If(
            args["interfaceID"].load() == INTERFACE_ARC72_METADATA,
            abi_return(BOOL_TRUE),
        ),
        abi_return(BOOL_FALSE),
    )


supportsInterface = ABI_Method(
    {
        "name": "supportsInterface",
        "desc": "Detects support for an interface specified by selector.",
        "readonly": True,
        "args": [
            {
                "type": "byte[4]",
                "name": "interfaceID",
                "desc": "The selector of the interface to detect.",
            },
        ],
        "returns": {
            "type": "bool",
            "desc": "Whether the contract supports the interface.",
        },
    },
    supportsInterfaceHandler,
)


def tokenByIndexHandler(args):
    return Seq(
        Assert(U256toi(args["index"].load()) < App.globalGet(Bytes("totalMinted"))),
        contents := App.box_get(Concat(Bytes("i"), args["index"].load())),
        Assert(contents.hasValue()),
        abi_return(contents.value()),
    )


tokenByIndex = ABI_Method(
    {
        "name": "arc72_tokenByIndex",
        "desc": "Returns the token ID of the token with the given index among all NFTs defined by the contract",
        "readonly": True,
        "args": [
            {"type": "uint256", "name": "index"},
        ],
        "returns": {"type": "uint256"},
    },
    tokenByIndexHandler,
)


def tokenURIHandler(args):
    return Seq(
        nft := NFT(args["tokenId"].load()),
        Assert(nft.exists()),
        abi_return(nft.get("metadata_uri")),
    )


tokenURI = ABI_Method(
    {
        "name": "arc72_tokenURI",
        "desc": "Returns a URI pointing to the NFT metadata",
        "readonly": True,
        "args": [
            {"type": "uint256", "name": "tokenId", "desc": "The ID of the NFT"},
        ],
        "returns": {"type": "byte[256]", "desc": "URI to token metadata."},
    },
    tokenURIHandler,
)


def totalSupplyHandler(_):
    return abi_return(Itou256(App.globalGet(Bytes("totalMinted"))))


totalSupply = ABI_Method(
    {
        "name": "arc72_totalSupply",
        "desc": "Returns the number of NFTs currently defined by this contract",
        "readonly": True,
        "args": [],
        "returns": {"type": "uint256"},
    },
    totalSupplyHandler,
)


def transferFromHandler(args):
    owner = ScratchVar(TealType.bytes)

    return Seq(
        nft := NFT(args["tokenId"].load()),
        owner.store(nft.get("owner")),
        isOperator := App.box_length(Concat(owner.load(), Txn.sender())),
        Assert(args["from"].load() == owner.load()),
        Assert(
            Or(
                Txn.sender() == nft.get("operator"),
                Txn.sender() == owner.load(),
                isOperator.hasValue(),
            )
        ),
        # we allow an optional txn before this one that covers the min balance
        # cost for the balance box. if it already exists, we will refund it
        If(
            Txn.group_index() > Int(0),
            If(
                is_algo_txn(
                    Txn.group_index() - Int(1),
                    MIN_BALANCE_BALANCE_BOX,
                    Global.current_application_address(),
                ),
                Seq(
                    length := App.box_length(Concat(Bytes("b"), args["to"].load())),
                    If(
                        length.hasValue(),
                        send_algo_cover_fee(
                            MIN_BALANCE_BALANCE_BOX,
                            Gtxn[Txn.group_index() - Int(1)].sender(),
                        ),
                    ),
                ),
            ),
        ),
        nft.transfer(owner.load(), args["to"].load()),
        abi_return(),
    )


transferFrom = ABI_Method(
    {
        "name": "arc72_transferFrom",
        "desc": "Transfers ownership of an NFT",
        "readonly": False,
        "args": [
            {"type": "address", "name": "from"},
            {"type": "address", "name": "to"},
            {"type": "uint256", "name": "tokenId"},
        ],
        "returns": {"type": "void"},
    },
    transferFromHandler,
)


def updateTokenURIHandler(args):
    return Seq(
        assert_is_creator(),
        nft := NFT(args["tokenId"].load()),
        Assert(nft.exists()),
        Assert(nft.is_revealed()),
        nft.set("metadata_uri", args["tokenURI"].load()),
        abi_event(
            EVENT_UPDATE_URI,
            Concat(
                args["tokenId"].load(),
                args["tokenURI"].load(),
            ),
        ),
        abi_return(),
    )


updateTokenURI = ABI_Method(
    {
        "name": "highforge_updateTokenURI",
        "desc": "Allows the creator to update the token URI for a token",
        "readonly": False,
        "args": [
            {"type": "uint256", "name": "tokenId", "desc": "The ID of the NFT"},
            {
                "type": "byte[256]",
                "name": "tokenURI",
                "desc": "The metadata URI for the token",
            },
        ],
        "returns": {"type": "void"},
    },
    updateTokenURIHandler,
)


################################################################################
# OnComplete Branches
################################################################################


def on_creation():
    return Seq(
        App.globalPut(Bytes("price"), Int(0)),
        # launch will be available when time >= launchStart
        # it will go until maxSupply is reached OR time > launchEnd
        App.globalPut(Bytes("maxSupply"), Int(0)),
        # (wl)launchStart and launchEnd are given in seconds since epoch
        App.globalPut(Bytes("launchStart"), Int(0)),
        App.globalPut(Bytes("launchEnd"), Int(0)),
        App.globalPut(Bytes("launchPaused"), Int(0)),
        # whitelist will start when time > wlLaunchStart
        # whitelist will end when time >= launchStart
        App.globalPut(Bytes("wlLaunchStart"), Int(0)),
        App.globalPut(Bytes("wlTokenID"), Int(0)),
        App.globalPut(Bytes("wlPrice"), Int(0)),
        App.globalPut(Bytes("wlAltID"), Int(0)),
        App.globalPut(Bytes("wlAltPrice"), Int(0)),
        App.globalPut(Bytes("wlMax"), Int(0)),
        App.globalPut(Bytes("wlMinted"), Int(0)),
        # launchpad fee is in basis points (defaults to 2.5%)
        App.globalPut(Bytes("launchpadFee"), Int(250)),
        App.globalPut(Bytes("nextMintID"), Int(1)),
        App.globalPut(Bytes("totalMinted"), Int(0)),
        App.globalPut(Bytes("charityAddress"), Global.current_application_address()),
        App.globalPut(Bytes("charityPoints"), Int(0)),
        Approve(),
    )


def on_closeout():
    return Reject()


def on_delete():
    return Seq(
        assert_is_creator(),
        Assert(App.globalGet(Bytes("totalMinted")) == Int(0)),
        If(
            App.globalGet(Bytes("wlAltID")),
            closeout_asset_to_creator(App.globalGet(Bytes("wlAltID"))),
        ),
        closeout_algo(Global.creator_address()),
        Approve(),
    )


def on_noop():
    return Cond(
        [Txn.application_args[0] == Bytes("claimAlgo"), on_claim_algo()],
        [Txn.application_args[0] == Bytes("claimWLAlt"), on_claim_wl_alt()],
        [Txn.application_args[0] == Bytes("claimWLToken"), on_claim_wl_token()],
        [Txn.application_args[0] == Bytes("disableWL"), on_disable_whitelist()],
        [Txn.application_args[0] == Bytes("enableWL"), on_enable_whitelist()],
        [Txn.application_args[0] == Bytes("setCharity"), on_set_charity()],
        [Txn.application_args[0] == Bytes("setLaunchDates"), on_set_launch_dates()],
        [Txn.application_args[0] == Bytes("setLaunchDetails"), on_set_launch_details()],
        [Txn.application_args[0] == Bytes("setLaunchPaused"), on_set_launch_paused()],
        [Txn.application_args[0] == Bytes("setLaunchpadFee"), on_set_launchpad_fee()],
        [Txn.application_args[0] == approve.selector, approve.handler()],
        [Txn.application_args[0] == balanceOf.selector, balanceOf.handler()],
        [Txn.application_args[0] == burn.selector, burn.handler()],
        [Txn.application_args[0] == getApproved.selector, getApproved.handler()],
        [
            Txn.application_args[0] == isApprovedForAll.selector,
            isApprovedForAll.handler(),
        ],
        [Txn.application_args[0] == mint.selector, mint.handler()],
        [Txn.application_args[0] == ownerOf.selector, ownerOf.handler()],
        [Txn.application_args[0] == reveal.selector, reveal.handler()],
        [
            Txn.application_args[0] == setApprovalForAll.selector,
            setApprovalForAll.handler(),
        ],
        [Txn.application_args[0] == setupBalance.selector, setupBalance.handler()],
        [
            Txn.application_args[0] == supportsInterface.selector,
            supportsInterface.handler(),
        ],
        [Txn.application_args[0] == tokenByIndex.selector, tokenByIndex.handler()],
        [Txn.application_args[0] == tokenURI.selector, tokenURI.handler()],
        [Txn.application_args[0] == totalSupply.selector, totalSupply.handler()],
        [Txn.application_args[0] == transferFrom.selector, transferFrom.handler()],
    )


def on_optin():
    return Reject()


def on_update():
    return Seq(assert_is_launch(), Approve())


################################################################################
# Program Construction
################################################################################


def approval_program():
    program = Seq(
        Assert(Txn.rekey_to() == Global.zero_address()),
        Cond(
            [Txn.application_id() == Int(0), on_creation()],
            [Txn.on_completion() == OnComplete.CloseOut, on_closeout()],
            [Txn.on_completion() == OnComplete.DeleteApplication, on_delete()],
            [Txn.on_completion() == OnComplete.NoOp, on_noop()],
            [Txn.on_completion() == OnComplete.OptIn, on_optin()],
            [Txn.on_completion() == OnComplete.UpdateApplication, on_update()],
        ),
    )

    return compileTeal(program, Mode.Application, version=9, assembleConstants=True)


def clear_program():
    program = on_closeout()
    return compileTeal(program, Mode.Application, version=9, assembleConstants=True)


p = Path(__file__).parent.absolute()
(p / f"arc72/{version}").mkdir(exist_ok=True)


with open(f"arc72/{version}/approval.teal", "w") as f:
    f.write(approval_program())

with open(f"arc72/{version}/clear.teal", "w") as f:
    f.write(clear_program())


import base64, hashlib, subprocess

subprocess.run(
    [
        "goal",
        "clerk",
        "compile",
        f"arc72/{version}/approval.teal",
        "-o",
        f"arc72/{version}/approval.bin",
    ]
)
subprocess.run(
    [
        "goal",
        "clerk",
        "compile",
        f"arc72/{version}/clear.teal",
        "-o",
        f"arc72/{version}/clear.bin",
    ]
)

with open(f"arc72/{version}/approval.bin", "rb") as f:
    contents = f.read()
    print("approvalHash", base64.b64encode(hashlib.sha256(contents).digest()).decode())
    with open(f"arc72/{version}/approval.b64", "w") as f:
        f.write(base64.b64encode(contents).decode())

with open(f"arc72/{version}/clear.bin", "rb") as f:
    contents = f.read()
    print("clearHash", base64.b64encode(hashlib.sha256(contents).digest()).decode())
    with open(f"arc72/{version}/clear.b64", "w") as f:
        f.write(base64.b64encode(contents).decode())

print("")
print("Copy approval.b64 and clear.b64 to algoseas-libs!!!")
