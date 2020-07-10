import base64
import copy
import thread
import socket
import sys
import os
import datetime
import time
import json
import threading
import signal

#META CONFIG FILES #
limit = 10           #max conn accepted
BUFFER_SZ = 2*1024
CACHE_DIR = "./cache"
BLACKLIST_FILE = "blacklist.txt"
USERNAME_PASSWORD_FILE = "username_password.txt"
MAX_CACHE_BUFFER = 3
NO_OF_OCC_FOR_CACHE = 3

getOrPost = None

blocked = []
admins = []


def cacheDirExists():
    """
    Check if the cache directory exists. If it does not create it
    """
    if not os.path.isdir(CACHE_DIR):
        os.makedirs(CACHE_DIR)

def add_log(fileurl, adrr_c):
    """
    Add the fileurl to the log
    """

    fileurl = fileurl.replace("/", "__")
    dt = time.strptime(time.ctime(), "%a %b %d %H:%M:%S %Y")
    if not fileurl in logs:
        logs[fileurl] = []
    logs[fileurl].append({
            "datetime" : dt,
            "client" : json.dumps(adrr_c),
        })
    
def getListOfBlockedSites():
    """
    Get a list of all the blocked websites
    """
    with open(BLACKLIST_FILE, "rb") as f:
        blocked = f.readlines()
        for i in range(len(blocked)):
            blocked[i] = blocked[i].rstrip()
    return blocked

def getListOfAdmins():
    """
    Get a list of all admins and their passwords 
    """
    with open(USERNAME_PASSWORD_FILE, "rb") as f:
        admins = f.readlines()
        for i in range(len(admins)):
            admins[i] = admins[i].rstrip()
            admins[i] = base64.b64encode(admins[i])
    return admins

def cacheCondition(fileurl):
    """
    Check to see if a cache has to be done or not 
    """
    
    try:
        log_arr = logs[fileurl.replace("/", "__")]
        checker = len(log_arr) - NO_OF_OCC_FOR_CACHE
        if (checker < 0) : 
            return False
        last = log_arr[checker]["datetime"]
        if  (datetime.datetime.fromtimestamp(time.mktime(last)) + datetime.timedelta(minutes=5) < datetime.datetime.now()):
            return False
        return True
    except Exception as e:
        print e
        return False

def cleanCache():
    """
    A function to clean up cache, i.e delete all the files in the cache
    """
    for file in os.listdir(CACHE_DIR):
        os.remove(CACHE_DIR + "/" + file)


def get_access(fileurl):
    """
    Lock fileurl, mutexlock kinda thing
    """
    if fileurl in locks:
        lock = locks[fileurl]
    else:
        lock = threading.Lock()
        locks[fileurl] = lock
    lock.acquire()



# take command line argument
if len(sys.argv) < 2:
    print "Usage: python %s <PROXY_PORT>" % sys.argv[0]
    print "Example: python %s 20100" % sys.argv[0]
    raise SystemExit


def leave_access(fileurl):
    """
    Unlock fileurl, mutex unlock kinda thing
    """
    if fileurl in locks:
        lock = locks[fileurl]
        lock.release()
    else:
        print "Lock problem"
        sys.exit()

def get_cache_details(adrr_c, details):
    """
    Collect all the information from the cached file
    """
    
    get_access(details["complete_url"])
    add_log(details["complete_url"], adrr_c)
    do_cache = cacheCondition(details["complete_url"])
    leave_access(details["complete_url"])
    details["do_cache"] = do_cache
    cache_path, mtime = get_current_cache_info(details["complete_url"])
    details["cache_path"] = cache_path
    details["mtime"] = mtime                     # refers to the last mtime
    return details



try:
    proxy_port = int(sys.argv[1])
except:
    print "provide proper port number"
    raise SystemExit

cacheDirExists()

blocked = getListOfBlockedSites()

admins = getListOfAdmins()

cleanCache()




def get_current_cache_info(fileurl):
    """
    Check to see if the file exists in the cache
    """

    cache_path = CACHE_DIR + "/" + fileurl.replace("/", "__")

    if fileurl.startswith("/"):
        fileurl = fileurl.replace("/", "", 1)


    if os.path.isfile(cache_path):
        mtime = time.strptime(time.ctime(os.path.getmtime(cache_path)), "%a %b %d %H:%M:%S %Y")
        return cache_path, mtime
    return cache_path, None



def freeCache(fileurl):
    """
    Delete the least recently used cache if the cache limit is reached
    """

    cache_files = os.listdir(CACHE_DIR)
    if len(cache_files) < MAX_CACHE_BUFFER:
        return
    for file in cache_files:
        get_access(file)
    
    mtime = logs[cache_files[0]][-1]["datetime"]    
    for file in cache_files:
        if logs[file][-1]["datetime"] < mtime[0]:
            mtime = logs[file][-1]["datetime"]
    
    leastRecentlyUsedCache = None
    for file in cache_files:
        if logs[file][-1]["datetime"] == mtime[0]:
            leastRecentlyUsedCache = file
            break
    os.remove(CACHE_DIR + "/" + leastRecentlyUsedCache)
    for file in cache_files:
        leave_access(file)


def parseDetails(adrr_c, client_data):

    """
    Get all the details and return it in the form of a dictionary
    """

    try:
        lines = removeEmptyLines(client_data)
        firstLineTok = lines[0].split()
        url = firstLineTok[1]
        authentLone = []
        url_pos = url.find("://")

        protocol = "http"

        if url_pos != -1:
            protocol = url[:url_pos]
            url = url[(url_pos+3):]
       
        port_pos = url.find(":")
        portflag = False
        path_pos = url.find("/")
        if path_pos == -1:
            path_pos = len(url)

        if port_pos == -1:
            portflag = True

        # Handle Request paths #

        if path_pos < port_pos or portflag:
            server_url = url[:path_pos]
            server_port = 80

        else:
            server_url = url[:port_pos]
            server_port = int(url[(port_pos+1):path_pos])


        authentiFlag = False
        
        
        for line in lines:
            if "Authorization" in line:
                authentLone.append(line)
                
        
        if len(authentLone):
            auth_b64 = auth_line[0].split()[2]
            authentiFlag = True
        else:
            auth_b64 = None
            

        firstLineTok[1] = url[path_pos:]
        if(authentiFlag):
            print "..."
        lines[0] = ' '.join(firstLineTok)
        client_data = "\r\n".join(lines) + '\r\n\r\n'
       
        return {
            "server_url" : server_url,
            "protocol" : protocol,
            "complete_url" : url,
            "method" : firstLineTok[0],
            "auth_b64" : auth_b64,
            "client_data" : client_data,
            "server_port" : server_port,


        }

    except Exception as e:
        print ""
        print e
        print ""
        return None

def removeEmptyLines(data):
    lines = data.splitlines()
    while lines[(len(lines)-1)] == '':
        lines.remove('')
    return lines

def insert_if_modified(details):
    """
    Insert the If Modified header used to keep the cache up to date
    """

    lines = removeEmptyLines( details["client_data"])
    header = time.strftime("%a %b %d %H:%M:%S %Y", details["mtime"])
    header = "If-Modified-Since: " + header
    lines.append(header)
    del header
    details["client_data"] = "\r\n".join(lines) + "\r\n\r\n"
    return details


def serve_get(socket_c, adrr_c, details):
    """
    Take care of GET requests
    """

    try:

        do_cache = details["do_cache"]
        mtime = details["mtime"]
        getOrPost = "GET"
        cache_path = details["cache_path"]
        client_data = details["client_data"]
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        print "Serving"
        print getOrPost
        server_socket.connect((details["server_url"], details["server_port"]))
        server_socket.send(details["client_data"])

        reply = server_socket.recv(BUFFER_SZ)
        print "..."
        if mtime and "304 Not Modified" in reply:
            print "Cached file returning"
            print "returning cached file %s to %s" % (cache_path, str(adrr_c))
            get_access(details["complete_url"])
            with open(cache_path,'rb') as f:
                chunk = f.read(BUFFER_SZ)
                while chunk:
                    socket_c.send(chunk)
                    chunk = f.read(BUFFER_SZ)
            leave_access(details["complete_url"])

        else:
            if do_cache:
                print "caching file while serving %s to %s" % (cache_path, str(adrr_c))
                print "..."
                freeCache(details["complete_url"])
                get_access(details["complete_url"])
                with open(cache_path, "w+") as f:
                    while len(reply):
                        socket_c.send(reply)
                        f.write(reply)
                        reply = server_socket.recv(BUFFER_SZ)
                leave_access(details["complete_url"])
                socket_c.send("\r\n\r\n")
            else:
                print "without caching serving %s to %s" % (cache_path, str(adrr_c))
                print "..."
                while len(reply):
                    socket_c.send(reply)
                    reply = server_socket.recv(BUFFER_SZ)
                print "Done serving"
                socket_c.send("\r\n\r\n")


        print "Request Done"
        server_socket.close()
        socket_c.close()
        return

    except Exception as e:
        print " "
        print e
        print " "
        server_socket.close()
        socket_c.close()
        return


def is_blocked(socket_c, adrr_c, details):
    """
    Handle blocked websites
    """
    blockedFlag = False
    if not (details["server_url"] + ":" + str(details["server_port"])) in blocked:
        return blockedFlag
    if not details["auth_b64"]:
        blockedFlag = True
        return blockedFlag
    if details["auth_b64"] in admins:
        return blockedFlag
    return True




def serve_post(socket_c, adrr_c, details):
    """
    Take care of POST requests
    """

    try:
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        print "Serving"
        server_socket.connect((details["server_url"], details["server_port"]))
        getOrPost = "POST"
        server_socket.send(details["client_data"])
        print getOrPost

        while True:
            reply = server_socket.recv(BUFFER_SZ)
            if len(reply):
                socket_c.send(reply)
            else:
                break

        print "Request Done"
        server_socket.close()
        socket_c.close()
        return

    except Exception as e:
        print e
        server_socket.close()
        socket_c.close()
        return




def start_proxy_server():
    """
    Creates the socket, whenever a connection is made, another thread is spawned to serve the request 
    """

    try:
        proxy_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        print "Starting server... "
        proxy_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        print ""
        proxy_socket.bind(('', proxy_port))
        print ""
        proxy_socket.listen(limit)
        print  "..."
        print "Serving proxy on %s port %s ..." % (str(proxy_socket.getsockname()[0]),str(proxy_socket.getsockname()[1]))

    except Exception as e:
        print ""
        print "Error found, proxy server could not be started..."
        print ""
        print e
        proxy_socket.close()
        raise SystemExit


    
    while True:
        try:
            print "Listening..."
            socket_c, adrr_c = proxy_socket.accept()
            client_data = socket_c.recv(BUFFER_SZ)

            split_client_data = client_data.splitlines()
            print "%s --> [%s] \"%s\"" % (str(adrr_c),str(datetime.datetime.now()),split_client_data[0])

            thread.start_new_thread( handleAReq_,
                (
                    socket_c,
                    adrr_c,
                    client_data
                )
            )

        except KeyboardInterrupt:
            print "\nProxy server shutting down ...\n"
            socket_c.close()
            print ""
            proxy_socket.close()
            break



def handleAReq_(socket_c, adrr_c, client_data):
    """
    A thread function which handles one request and takes care of the rest 
    
    """

    details = parseDetails(adrr_c, client_data)

    if not details:
        socket_c.close()
        print "Details not found"
        return

    isb = is_blocked(socket_c, adrr_c, details)
    if isb:
        print "Block status : ", isb
        socket_c.send("HTTP/1.0 200 OK\r\n")
        socket_c.send("Content-Length: 11\r\n")
        socket_c.send("\r\n")
        socket_c.send("Error\r\n")
        socket_c.send("\r\n\r\n")
        socket_c.close()
        print "closed"
        return 

    if details["method"] == "POST":
        serve_post(socket_c, adrr_c, details)


    elif details["method"] == "GET":
        details = get_cache_details(adrr_c, details)
        if details["mtime"]:
            details = insert_if_modified(details)
        serve_get(socket_c, adrr_c, details)

    

    print adrr_c
    print "closed\n"
    socket_c.close()
    

logs = {}
locks = {}
start_proxy_server()