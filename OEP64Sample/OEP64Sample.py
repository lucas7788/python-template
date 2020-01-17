"""
An Example of OEP-64
"""
from ontology.interop.Ontology.Contract import Migrate
from ontology.interop.System.Action import RegisterAction
from ontology.interop.Ontology.Runtime import Base58ToAddress
from ontology.interop.System.Storage import Get, GetContext, Put
from ontology.builtins import sha256, concat
from ontology.interop.System.Runtime import Serialize, Deserialize, Log, CheckWitness, GetTime, Notify

# vote status
STATUS_NOT_FOUND = 'not found'

# pre + hash -> topic
PRE_TOPIC = '01'
# topic_info + hash -> topicInfo:[admin, topic_title, topic_detail, voter address,startTime, endTime, approve amount,
# reject amount, status, topic hash]
PRE_TOPIC_INFO = '02'

# pre + hash -> voted address: [['address1', 1],['address2',2]]
PRE_VOTED = '03'


# key -> all topic hash
KEY_ALL_TOPIC_HASH = 'all_hash'
# key -> all admin
KEY_ADMINS = 'all_admin'

ctx = GetContext()
SUPER_ADMIN = Base58ToAddress("AbtTQJYKfQxq4UdygDsbLVjE8uRrJ2H3tP")

CreateTopicEvent = RegisterAction("createTopic", "hash", "topic_title", "topic_detail")
VoteTopicEvent = RegisterAction("voteTopic", "hash", "voter")
VoteTopicEndEvent = RegisterAction("voteTopicEnd", "hash", "voter")


def Main(operation, args):
    """
    only super admin can invoke
    """
    if operation == 'init':
        return init()
    if operation == 'setAdmin':
        Require(len(args) == 1)
        admins = args[0]
        return setAdmin(admins)
    if operation == 'upgrade':
        Require(len(args) == 7)
        code = args[0]
        needStorage = args[1]
        name = args[2]
        version = args[3]
        author = args[4]
        email = args[5]
        desc = args[6]
        return upgrade(code, needStorage, name, version, author, email, desc)
    """
    only admin can invoke
    """
    if operation == 'createTopic':
        Require(len(args) == 6)
        admin = args[0]
        topic_title = args[1]
        topic_detail = args[2]
        start_time = args[3]
        end_time = args[4]
        voters = args[5]
        return createTopic(admin, topic_title, topic_detail, start_time, end_time, voters)
    if operation == 'cancelTopic':
        Require(len(args) == 1)
        hash = args[0]
        return cancelTopic(hash)
    if operation == 'setVoterForTopic':
        Require(len(args) == 2)
        hash = args[0]
        voters = args[1]
        return setVoterForTopic(hash, voters)
    # all user can invoke
    if operation == 'listAdmins':
        return listAdmins()
    if operation == 'listTopics':
        Require(len(args) == 0)
        return listTopics()
    if operation == 'getTopic':
        Require(len(args) == 1)
        hash = args[0]
        return getTopic(hash)
    if operation == 'getTopicInfo':
        Require(len(args) == 1)
        hash = args[0]
        return getTopicInfo(hash)
    if operation == 'getVoters':
        Require(len(args) == 1)
        hash = args[0]
        return getVoters(hash)
    if operation == 'voteTopic':
        Require(len(args) == 3)
        hash = args[0]
        voter = args[1]
        approveOrReject = args[2]
        return voteTopic(hash, voter, approveOrReject)
    if operation == 'getVotedInfo':
        Require(len(args) == 2)
        hash = args[0]
        addr = args[1]
        return getVotedInfo(hash, addr)
    if operation == 'getVotedAddress':
        Require(len(args) == 1)
        hash = args[0]
        return getVotedAddress(hash)
    if operation == "getTopicInfoListByAdmin":
        Require(len(args) == 1)
        admin = args[0]
        return getTopicInfoListByAdmin(admin)
    return False


# ****only super admin can invoke*********
def init():
    RequireWitness(SUPER_ADMIN)
    info = Get(ctx, KEY_ADMINS)
    assert(info == None)
    Put(ctx, KEY_ADMINS, Serialize([SUPER_ADMIN]))
    return True


# only SuperAdmin can invoke this method
def setAdmin(admins):
    RequireWitness(SUPER_ADMIN)
    for admin in admins:
        RequireIsAddress(admin)
    Put(ctx, KEY_ADMINS, Serialize(admins))
    return True


# upgrade contract
def upgrade(code, needStorage, name, version, author, email, desc):
    RequireWitness(SUPER_ADMIN)
    r = Migrate(code, needStorage, name, version, author, email, desc)
    Require(r is True)
    Notify(["Migrate successfully"])
    return True


# query all admins
def listAdmins():
    info = Get(ctx, KEY_ADMINS)
    if info == None:
        return []
    return Deserialize(info)


# ****only admin can invoke*********
# [admin, topic_title, topic_detail, voter address,startTime, endTime, approve amount, reject amount, status,topic hash]
# create a voting topic, only admin can invoke this method
def createTopic(admin, topic_title, topic_detail, startTime, endTime, voters):
    RequireWitness(admin)
    Require(isAdmin(admin))
    Require(startTime < endTime)
    for voter in voters:
        Require(len(voter) == 2)
        RequireIsAddress(voter[0])
    hash = sha256(concat(topic_title, topic_detail))
    keyTopic = getKey(PRE_TOPIC, hash)
    data = Get(ctx, keyTopic)
    Require(data is None)
    Put(ctx, keyTopic, Serialize([topic_title, topic_detail]))
    keyTopicInfo = getKey(PRE_TOPIC_INFO, hash)
    topicInfo = [admin, topic_title, topic_detail, voters, startTime, endTime, 0, 0, 1, hash]
    Put(ctx, keyTopicInfo, Serialize(topicInfo))
    hashs = []
    bs = Get(ctx, KEY_ALL_TOPIC_HASH)
    if bs:
        hashs = Deserialize(bs)
    hashs.append(hash)
    Put(ctx, KEY_ALL_TOPIC_HASH, Serialize(hashs))
    CreateTopicEvent(hash, topic_title, topic_detail)
    return True

def cancelTopic(hash):
    topicInfo = getTopicInfo(hash)
    Require(len(topicInfo) == 10)
    Require(topicInfo[8] == 1)
    RequireWitness(topicInfo[0])
    topicInfo[8] = 0
    key = getKey(PRE_TOPIC_INFO, hash)
    Put(ctx, key, Serialize(topicInfo))
    return True

# set voters for topic, only these voter can vote, [[voter1, weight1],[voter2, weight2]]
def setVoterForTopic(hash, voters):
    Require(len(voters) != 0)
    for voter in voters:
        Require(len(voter) == 2)
        RequireIsAddress(voter[0])
    key = getKey(PRE_TOPIC_INFO, hash)
    info = Get(ctx, key)
    Require(info is not None)
    topicInfo = Deserialize(info)
    RequireWitness(topicInfo[0])
    topicInfo[3] = voters
    Put(ctx, key, Serialize(topicInfo))
    return True


# ****all user can invoke method ***********
# query all topic hash
def listTopics():
    bs = Get(ctx, KEY_ALL_TOPIC_HASH)
    if bs == None:
        return []
    else:
        return Deserialize(bs)

# query topicInfo by admin
def getTopicInfoListByAdmin(admin):
    hashs = listTopics()
    res = []
    for hash in hashs:
        topicInfo = getTopicInfo(hash)
        if topicInfo[0] == admin:
            res.append(topicInfo)
    return res

# query topic title and topic detail by topic hash, [topic_title, topic_detail]
def getTopic(hash):
    key = getKey(PRE_TOPIC, hash)
    info = Get(ctx, key)
    if info is None:
        return []
    else:
        return Deserialize(info)


# query topicInfo including [admin, topic, voter address,startTime, endTime, approve amount, reject amount, state,
# topic hash]
def getTopicInfo(hash):
    key = getKey(PRE_TOPIC_INFO, hash)
    info = Get(ctx, key)
    if info is None:
        return []
    return Deserialize(info)

# query voters of the topic
def getVoters(hash):
    key = getKey(PRE_TOPIC_INFO, hash)
    info = Get(ctx, key)
    if info == None:
        return []
    topicInfo = Deserialize(info)
    return topicInfo[3]


# vote topic, only voter who authored by topic admin can invoke
# [admin, topic_title, topic_detail, voter address,startTime, endTime, approve amount, reject amount, status,
#  topic hash]
def voteTopic(hash, voter, approveOrReject):
    RequireWitness(voter)
    if isValidVoter(hash, voter) is False:
        Notify(["isValidVoter failed"])
        return False
    votedInfo = getVotedInfo(hash, voter)
    if votedInfo == 1:
        Require(approveOrReject is False)
    if votedInfo == 2:
        Require(approveOrReject is True)
    topicInfo = getTopicInfo(hash)
    if len(topicInfo) != 10:
        Notify(["len(topicInfo) is wrong"])
        return False
    if topicInfo[8] != 1:
        Notify(["canceled topic"])
        return False
    cur = GetTime()
    if cur < topicInfo[4]:
        Notify(["not start"])
        return False
    if cur >= topicInfo[5]:
        Notify(["has end"])
        return False
    if approveOrReject:
        topicInfo[6] += getVoterWeight(voter, hash)
        if votedInfo == 2:
            topicInfo[7] -= getVoterWeight(voter, hash)
    else:
        topicInfo[7] += getVoterWeight(voter, hash)
        if votedInfo == 1:
            topicInfo[6] -= getVoterWeight(voter, hash)
    keyTopicInfo = getKey(PRE_TOPIC_INFO, hash)
    Put(ctx, keyTopicInfo, Serialize(topicInfo))
    updateVotedAddress(voter, hash, approveOrReject)
    VoteTopicEvent(hash, voter)
    return True

# query the weight of voter
def getVoterWeight(voter, hash):
    voters = getVoters(hash)
    for voter_item in voters:
        if voter_item[0] == voter:
            return voter_item[1]
    return 0

# 1: approve, 2: reject, other: not voted
def getVotedInfo(hash, voter):
    key = getKey(PRE_VOTED, hash)
    info = Get(ctx, key)
    if info == None:
        return 0
    votedInfos = Deserialize(info)
    for votedInfo in votedInfos:
        if votedInfo[0] == voter:
            return votedInfo[1]
    return 0

def isValidVoter(hash, voter):
    voters = getVoters(hash)
    for addr in voters:
        if addr[0] == voter:
            return True
    return False

# [['Address', 1],['Address', 2]], 1. true 2. false
def updateVotedAddress(voter, hash, approveOrReject):
    key = getKey(PRE_VOTED, hash)
    info = Get(ctx, key)
    votedAddrs = []
    if info != None:
        votedAddrs = Deserialize(info)
        for voteInfo in votedAddrs:
            if voteInfo[0] == voter:
                if approveOrReject:
                    voteInfo[1] = 1
                else:
                    voteInfo[1] = 2
                Put(ctx, key, Serialize(votedAddrs))
                return True
    if approveOrReject:
        votedAddrs.append([voter, 1])
    else:
        votedAddrs.append([voter, 2])
    Put(ctx, key, Serialize(votedAddrs))
    return True

def getVotedAddress(hash):
    key = getKey(PRE_VOTED, hash)
    info = Get(ctx, key)
    votedAddrs = []
    if info != None:
        votedAddrs = Deserialize(info)
    return votedAddrs

def getKey(pre, hash):
    '''
    Gets the storage key for looking up a balance
    :param address:
    '''
    key = concat(pre, hash)  # pylint: disable=E0602
    return key

def isAdmin(admin):
    '''
    need admin signature
    '''
    admins = listAdmins()
    for item in admins:
        if item == admin:
            return True
    return False

def RequireWitness(address):
    '''
    Raises an exception if the given address is not a witness.
    :param address: The address to check.
    '''
    Require(CheckWitness(address), "Address is not witness")


def Require(expr, message="There was an error"):
    '''
    Raises an exception if the given expression is false.
    :param expr: The expression to evaluate.
    :param message: The error message to log.
    '''
    if not expr:
        Log(message)
        raise Exception(message)

def RequireIsAddress(address):
    '''
    Raises an exception if the given address is not the correct length.
    :param address: The address to check.
    '''
    Require(len(address) == 20, "Address has invalid length")