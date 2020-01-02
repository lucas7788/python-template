"""
An Example of OEP-11
"""
from ontology.interop.System.Action import RegisterAction
from ontology.interop.Ontology.Runtime import Base58ToAddress
from ontology.interop.System.Storage import Get, GetContext, Put
from ontology.builtins import sha256, concat
from ontology.interop.System.Runtime import Serialize, Deserialize, Log, CheckWitness,GetTime

# vote status
STATUS_NOT_FOUND = 'not found'

# pre + hash -> topic
PRE_TOPIC = '01'
# topic_info + hash -> topicInfo:[admin, topic, voter address,startTime, endTime, approve amount, reject amount]
PRE_TOPIC_INFO = '02'

# pre + hash -> voted address: ['address1','address2']
# pre + hash + voter address -> approveOrReject: 1.approve, 2. reject, others. not voted
PRE_VOTED = '03'


# key -> all topic hash
KEY_ALL_TOPIC_HASH = 'all_hash'
# key -> all admin
KEY_ADMINS = 'all_admin'

ctx = GetContext()
SUPER_ADMIN = Base58ToAddress("AbtTQJYKfQxq4UdygDsbLVjE8uRrJ2H3tP")

CreateTopicEvent = RegisterAction("createTopic", "hash", "topic")
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
    """
    only admin can invoke
    """
    if operation == 'createTopic':
        Require(len(args) == 4)
        admin = args[0]
        topic = args[1]
        startTime = args[2]
        endTime = args[3]
        return createTopic(admin, topic, startTime, endTime)
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
    return False

# ****only super admin can invoke*********
def init():
    RequireWitness(SUPER_ADMIN)
    info = Get(ctx, KEY_ADMINS)
    if info:
        return False
    Put(ctx, KEY_ADMINS, Serialize([SUPER_ADMIN]))
    return True

# only SuperAdmin can invoke this method
def setAdmin(admins):
    RequireWitness(SUPER_ADMIN)
    for admin in admins:
        RequireIsAddress(admin)
    Put(ctx, KEY_ADMINS, Serialize(admins))
    return True
# query all admins
def listAdmins():
    info = Get(ctx, KEY_ADMINS)
    if info == None:
        return []
    return Deserialize(info)

# ****only admin can invoke*********
# create a voting topic, only admin can invoke this method
def createTopic(admin, topic, startTime, endTime):
    RequireWitness(admin)
    Require(isAdmin(admin))
    hash = sha256(topic)
    keyTopic = getKey(PRE_TOPIC, hash)
    data = Get(ctx, keyTopic)
    if data:
        return False
    Put(ctx, keyTopic, topic)
    keyTopicInfo = getKey(PRE_TOPIC_INFO, hash)
    topicInfo = [admin, topic, [], startTime, endTime, 0, 0]  #[admin, topic, voter address,startTime, endTime, approve amount, reject amount]
    Put(ctx, keyTopicInfo, Serialize(topicInfo))
    hashs = []
    bs = Get(ctx, KEY_ALL_TOPIC_HASH)
    if bs:
        hashs = Deserialize(bs)
    hashs.append(hash)
    Put(ctx, KEY_ALL_TOPIC_HASH, Serialize(hashs))
    CreateTopicEvent(hash, topic)
    return True

# set voters for topic, only these voter can vote, [[voter1, weight1],[voter2, weight2]]
def setVoterForTopic(hash, voters):
    key = getKey(PRE_TOPIC_INFO, hash)
    info = Get(ctx, key)
    if info == None:
        return False
    topicInfo = Deserialize(info)
    RequireWitness(topicInfo[0])
    topicInfo[2] = voters
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

# query topic content by topic hash
def getTopic(hash):
    key = getKey(PRE_TOPIC, hash)
    return Get(ctx, key)

# query topicInfo including [admin, topic, voter address,startTime, endTime, approve amount, reject amount]
def getTopicInfo(hash):
    key = getKey(PRE_TOPIC_INFO, hash)
    info = Get(ctx, key)
    if info == None:
        return []
    return Deserialize(info)

# query voters of the topic
def getVoters(hash):
    key = getKey(PRE_TOPIC_INFO, hash)
    info = Get(ctx, key)
    if info == None:
        return []
    topicInfo = Deserialize(info)
    return topicInfo[2]

# vote topic, only voter who authored by topic admin can invoke
def voteTopic(hash, voter, approveOrReject):
    RequireWitness(voter)
    Require(isValidVoter(hash, voter))
    votedInfo = 0
    if hasVoted(hash, voter): # has voted
        votedInfo = getVotedInfo(hash, voter)
        if votedInfo == 1 and approveOrReject:
            return False
        if votedInfo == 2 and approveOrReject == False:
            return False
    topicInfo = getTopicInfo(hash)
    if len(topicInfo) != 7:
        return False        #[admin, topic, voter address,startTime, endTime, approve amount, reject amount]
    cur = GetTime()
    if cur < topicInfo[3] or cur > topicInfo[4]:
        return False
    if approveOrReject:
        Put(ctx, getKey(getKey(PRE_VOTED, hash), voter), 1)
        topicInfo[5] += getVoterWeight(voter, hash)
        if votedInfo == 2:
            topicInfo[6] -= getVoterWeight(voter, hash)
    else:
        Put(ctx, getKey(getKey(PRE_VOTED, hash), voter), 2)
        topicInfo[6] += getVoterWeight(voter, hash)
        if votedInfo == 1:
            topicInfo[5] -= getVoterWeight(voter, hash)
    keyTopicInfo = getKey(PRE_TOPIC_INFO, hash)
    Put(ctx, keyTopicInfo, Serialize(topicInfo))
    updateVotedAddress(voter, hash)
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
    key = getKey(getKey(PRE_VOTED, hash), voter)
    return Get(ctx, key)

def isValidVoter(hash, voter):
    voters = getVoters(hash)
    for addr in voters:
        if addr[0] == voter:
            return True
    return False


def updateVotedAddress(voter, hash):
    key = getKey(PRE_VOTED, hash)
    info = Get(ctx, key)
    votedAddrs = []
    if info != None:
        votedAddrs = Deserialize(info)
    votedAddrs.append(voter)
    Put(ctx, key, Serialize(votedAddrs))
    return


def hasVoted(hash, voter):
    key = getKey(getKey(PRE_VOTED, hash), voter)
    info = Get(ctx, key)
    if info == None:
        return False
    return True


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