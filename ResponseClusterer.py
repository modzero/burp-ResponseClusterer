from burp import IBurpExtender
from burp import ITab
from burp import IHttpListener
from burp import IMessageEditorController
from burp import IHttpRequestResponse
from burp import IHttpService
from java.awt import Component
from java.awt import GridBagLayout
from java.awt import GridBagConstraints
from java.awt.event import ActionListener
from java.io import PrintWriter
from java.util import ArrayList
from java.util import List
from javax.swing import JScrollPane
from javax.swing import JSplitPane
from javax.swing import JTabbedPane
from javax.swing import JTable
from javax.swing import JPanel
from javax.swing import JLabel
from javax.swing.event import DocumentListener
from javax.swing import JCheckBox
from javax.swing import SwingUtilities
from javax.swing import JTextField
from javax.swing.table import AbstractTableModel
from threading import Lock

import difflib
import time
import urlparse
import pickle

class BurpExtender(IBurpExtender, ITab, IHttpListener, IMessageEditorController, AbstractTableModel, ActionListener, DocumentListener):
    
    #
    # implement IBurpExtender
    #
    
    def	registerExtenderCallbacks(self, callbacks):
    
        # keep a reference to our callbacks object
        self._callbacks = callbacks
        
        # obtain an extension helpers object
        self._helpers = callbacks.getHelpers()
        
        # set our extension name
        callbacks.setExtensionName("Response Clusterer")
        
        # create the log and a lock on which to synchronize when adding log entries
        self._log = ArrayList()
        self._lock = Lock()
        
        # main split pane
        self._main_jtabedpane = JTabbedPane()
        
        # The split pane with the log and request/respponse details
        self._splitpane = JSplitPane(JSplitPane.VERTICAL_SPLIT)
                
        # table of log entries
        logTable = Table(self)
        scrollPane = JScrollPane(logTable)
        self._splitpane.setLeftComponent(scrollPane)
        
        # List of log entries
        self._log_entries = []

        # tabs with request/response viewers
        tabs = JTabbedPane()
        self._requestViewer = callbacks.createMessageEditor(self, False)
        self._responseViewer = callbacks.createMessageEditor(self, False)
        tabs.addTab("Request", self._requestViewer.getComponent())
        tabs.addTab("Response", self._responseViewer.getComponent())
        self._splitpane.setRightComponent(tabs)
        
        #Setup the options
        self._optionsJPanel = JPanel()
        gridBagLayout = GridBagLayout()
        gbc = GridBagConstraints()
        self._optionsJPanel.setLayout(gridBagLayout)
        
        self.max_clusters = 500
        self.JLabel_max_clusters = JLabel("Maximum amount of clusters: ")
        gbc.gridy=0
        gbc.gridx=0
        self._optionsJPanel.add(self.JLabel_max_clusters, gbc)
        self.JTextField_max_clusters = JTextField(str(self.max_clusters), 5)
        self.JTextField_max_clusters.getDocument().addDocumentListener(self)
        gbc.gridx=1
        self._optionsJPanel.add(self.JTextField_max_clusters, gbc)
        callbacks.customizeUiComponent(self.JLabel_max_clusters)
        callbacks.customizeUiComponent(self.JTextField_max_clusters)
        
        self.similarity = 0.95
        self.JLabel_similarity = JLabel("Similarity (between 0 and 1)")
        gbc.gridy=1
        gbc.gridx=0
        self._optionsJPanel.add(self.JLabel_similarity, gbc)
        self.JTextField_similarity = JTextField(str(self.similarity), 5)
        self.JTextField_similarity.getDocument().addDocumentListener(self)
        gbc.gridx=1
        self._optionsJPanel.add(self.JTextField_similarity, gbc)
        callbacks.customizeUiComponent(self.JLabel_similarity)
        callbacks.customizeUiComponent(self.JTextField_similarity)
        
        self.use_quick_similar = False
        self.JLabel_use_quick_similar = JLabel("Use set intersection of space splitted tokens for similarity (default: optimized difflib.SequenceMatcher.quick_ratio)")
        gbc.gridy=2
        gbc.gridx=0
        self._optionsJPanel.add(self.JLabel_use_quick_similar, gbc)
        self.JCheckBox_use_quick_similar = JCheckBox("")
        self.JCheckBox_use_quick_similar.addActionListener(self)
        gbc.gridx=1
        self._optionsJPanel.add(self.JCheckBox_use_quick_similar, gbc)
        callbacks.customizeUiComponent(self.JCheckBox_use_quick_similar)
        
        self.response_max_size = 10*1024 #10kb
        self.JLabel_response_max_size = JLabel("Response max size (bytes)")
        gbc.gridy=3
        gbc.gridx=0
        self._optionsJPanel.add(self.JLabel_response_max_size, gbc)
        self.JTextField_response_max_size = JTextField(str(self.response_max_size), 5)
        self.JTextField_response_max_size.getDocument().addDocumentListener(self)
        gbc.gridx=1
        self._optionsJPanel.add(self.JTextField_response_max_size, gbc)
        callbacks.customizeUiComponent(self.JLabel_response_max_size)
        callbacks.customizeUiComponent(self.JTextField_response_max_size)
        
        self.uninteresting_mime_types = ('JPEG', 'CSS', 'GIF', 'script', 'GIF', 'PNG', 'image')
        self.uninteresting_status_codes = ()
        self.uninteresting_url_file_extensions = ('js', 'css', 'zip', 'war', 'jar', 'doc', 'docx', 'xls', 'xlsx', 'pdf', 'exe', 'dll', 'png', 'jpeg', 'jpg', 'bmp', 'tif', 'tiff', 'gif', 'webp', 'm3u', 'mp4', 'm4a', 'ogg', 'aac', 'flac', 'mp3', 'wav', 'avi', 'mov', 'mpeg', 'wmv', 'swf', 'woff', 'woff2')
        
        about = "<html>"
        about += "Author: floyd, @floyd_ch, http://www.floyd.ch<br>"
        about += "modzero AG, http://www.modzero.ch<br>"
        about += "<br>"
        about += "<h3>Getting an overview of the tested website</h3>"
        about += "<p style=\"width:500px\">"        
        about += "This plugin clusters all response bodies by similarity and shows a summary, one request/response per cluster. "
        about += 'Adjust similarity in the options if you get too few or too many entries in the "One member of each cluster" '
        about += "tab. The plugin will allow a tester to get an overview of the tested website's responses from all tools (scanner, proxy, etc.). "
        about += "As similarity comparison "
        about += "can use a lot of ressources, only small, in-scope responses that have interesting response codes, "
        about += "file extensions and mime types are processed. "
        about += "</p>"
        about += "</html>"
        self.JLabel_about = JLabel(about)
        self.JLabel_about.setLayout(GridBagLayout())
        self._aboutJPanel = JScrollPane(self.JLabel_about)
        
        # customize our UI components
        callbacks.customizeUiComponent(self._splitpane)
        callbacks.customizeUiComponent(logTable)
        callbacks.customizeUiComponent(scrollPane)
        callbacks.customizeUiComponent(tabs)
        
        # add the splitpane and options to the main jtabedpane
        self._main_jtabedpane.addTab("One member of each cluster", None, self._splitpane, None)
        self._main_jtabedpane.addTab("Options", None, self._optionsJPanel, None)		
        self._main_jtabedpane.addTab("About & README", None, self._aboutJPanel, None)
        
        # add the custom tab to Burp's UI
        callbacks.addSuiteTab(self)
        
        # register ourselves as an HTTP listener
        callbacks.registerHttpListener(self)
        
        # clusters will grow up to self.max_clusters response bodies...
        self._clusters = set()        
        self.Similarity = Similarity()
        
        # Now load the already stored 
        self._lock.acquire()
        log_entries_from_storage = self.load_project_setting("log_entries")
        if log_entries_from_storage:
            for toolFlag, req, resp, url in log_entries_from_storage:
                self.add_new_log_entry(toolFlag, req, resp, url)
        self._lock.release()
        
    #
    # implement what happens when options are changed
    #
    
    def changedUpdate(self, document):
        pass
    
    def removeUpdate(self, document):
        self.actionPerformed(None)
    
    def insertUpdate(self, document):
        self.actionPerformed(None)
    
    def actionPerformed(self, actionEvent):
        self._lock.acquire()
        self.use_quick_similar = self.JCheckBox_use_quick_similar.isSelected()
        try:
            self.max_clusters = int(self.JTextField_max_clusters.getText())
        except:
            self.JTextField_max_clusters.setText("200")
            
        try:
            self.similarity = float(self.JTextField_similarity.getText())
            if self.similarity > 1.0 or self.similarity < 0.0:
                self.JTextField_similarity.setText("0.9")
        except:
            self.JTextField_similarity.setText("0.9")
        
        try:
            self.response_max_size = float(self.JTextField_response_max_size.getText())
            if self.response_max_size < 0.0:
                self.JTextField_response_max_size.setText(str(10*1024))
        except:
            self.JTextField_response_max_size.setText(str(10*1024))
        
        print self.JCheckBox_use_quick_similar.isSelected(), self.JTextField_max_clusters.getText(), self.JTextField_similarity.getText(), self.JTextField_response_max_size.getText()
        
        self._lock.release()
    #
    # implement ITab
    #
    
    def getTabCaption(self):
        return "Response Clusterer"
    
    def getUiComponent(self):
        return self._main_jtabedpane
        
    #
    # implement IHttpListener
    #
    
    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        if not messageIsRequest:
            if len(self._clusters) >= self.max_clusters:
                return
            resp = messageInfo.getResponse()
            if len(resp) >= self.response_max_size:
                print "Message was too long"
                return
            iResponseInfo = self._helpers.analyzeResponse(resp)
            mime_type = iResponseInfo.getStatedMimeType()
            if mime_type in self.uninteresting_mime_types:
                print "Mime type", mime_type, "is ignored"
                return
            if iResponseInfo.getStatusCode() in self.uninteresting_status_codes:
                print "Status code", iResponseInfo.getStatusCode(), "is ignored"
                return
            req = messageInfo.getRequest()
            iRequestInfo = self._helpers.analyzeRequest(messageInfo)
            if '.' in iRequestInfo.getUrl().getFile() and iRequestInfo.getUrl().getFile().split('.')[-1] in self.uninteresting_url_file_extensions:
                print iRequestInfo.getUrl().getFile().split('.')[-1], "is an ignored file extension"
                return
            if not self._callbacks.isInScope(iRequestInfo.getUrl()):
                print iRequestInfo.getUrl(), "is not in scope"
                return
            body = resp[iResponseInfo.getBodyOffset():]
            self._lock.acquire()
            start_time = time.time()
            for response_code, item in self._clusters:
                if not response_code == iResponseInfo.getStatusCode():
                    #Different response codes -> different clusters
                    continue
                similarity_func = self.Similarity.similar
                if self.use_quick_similar:
                    similarity_func = self.Similarity.quick_similar
                if similarity_func(str(body), str(item), self.similarity):
                    self._lock.release()
                    return #break
            else: #when no break/return occures in the for loop    
                self.add_new_log_entry(toolFlag, req, resp, iRequestInfo.getUrl().toString())
                self.save_project_setting("log_entries", self._log_entries)
            taken_time = time.time() - start_time
            if taken_time > 0.5:
                print "Plugin took", taken_time, "seconds to process request... body length:", len(body), "current cluster length:", len(self._clusters)
                print "URL:", str(iRequestInfo.getUrl()), 
            self._lock.release()
    
    def add_new_log_entry(self, toolFlag, request, response, service_url):
        self._log_entries.append((toolFlag, request, response, service_url))
        iResponseInfo = self._helpers.analyzeResponse(response)
        body = response[iResponseInfo.getBodyOffset():]
        self._clusters.add((iResponseInfo.getStatusCode(), body))
        row = self._log.size()
        service = CustomHttpService(service_url)
        r = CustomRequestResponse(None, None, service, request, response)
        iRequestInfo = self._helpers.analyzeRequest(r)
        self._log.add(LogEntry(toolFlag, self._callbacks.saveBuffersToTempFiles(r), iRequestInfo.getUrl()))
        self.fireTableRowsInserted(row, row)
    
    #
    # extend AbstractTableModel
    #
    
    def getRowCount(self):
        try:
            return self._log.size()
        except:
            return 0

    def getColumnCount(self):
        return 2

    def getColumnName(self, columnIndex):
        if columnIndex == 0:
            return "Tool"
        if columnIndex == 1:
            return "URL"
        return ""

    def getValueAt(self, rowIndex, columnIndex):
        logEntry = self._log.get(rowIndex)
        if columnIndex == 0:
            return self._callbacks.getToolName(logEntry._tool)
        if columnIndex == 1:
            return logEntry._url.toString()
        return ""

    #
    # implement IMessageEditorController
    # this allows our request/response viewers to obtain details about the messages being displayed
    #
    
    def getHttpService(self):
        return self._currentlyDisplayedItem.getHttpService()

    def getRequest(self):
        return self._currentlyDisplayedItem.getRequest()

    def getResponse(self):
        return self._currentlyDisplayedItem.getResponse()
    
    def save_project_setting(self, name, value):
        value = pickle.dumps(value).encode("base64")
        request = "GET /"+name+" HTTP/1.0\r\n\r\n" \
                  "You can ignore this item in the site map. It was created by the ResponseClusterer extension. The \n" \
                  "reason is that the Burp API is missing a certain functionality to save settings. \n" \
                  "TODO Burp API limitation: This is a hackish way to be able to store project-scope settings.\n" \
                  "We don't want to restore requests/responses of tabs in a totally different Burp project.\n" \
                  "However, unfortunately there is no saveExtensionProjectSetting in the Burp API :(\n" \
                  "So we have to abuse the addToSiteMap API to store project-specific things\n" \
                  "Even when using this hack we currently cannot persist Collaborator interaction checks\n" \
                  "(IBurpCollaboratorClientContext is not serializable and Threads loose their Python class\n" \
                  "functionality when unloaded) due to Burp API limitations."
        response = None
        if value:
            response = "HTTP/1.1 200 OK\r\n" + value
        rr = CustomRequestResponse(name, '', CustomHttpService('http://responseclustererextension.local/'), request, response)
        self._callbacks.addToSiteMap(rr)

    def load_project_setting(self, name):
        rrs = self._callbacks.getSiteMap('http://responseclustererextension.local/'+name)
        if rrs:
            rr = rrs[0]
            if rr.getResponse():
                val = "\r\n".join(FloydsHelpers.jb2ps(rr.getResponse()).split("\r\n")[1:])
                return pickle.loads(val.decode("base64"))
            else:
                return None
        else:
            return None
        

class Similarity(object):
    
    def quick_similar(self, a, b, threshold=0.9):
        if threshold <= 0:
            return True
        elif threshold >= 1.0:
            return a == b
        
        set_a = set(a.split(' '))
        set_b = set(b.split(' '))
        
        if len(set_a) < 10 or len(set_b) < 10:
            return self.similar(a, b, threshold)
        else:
            return threshold < float(len(set_a.intersection(set_b))) / max(len(set_a), len(set_b))
    
    def similar(self, a, b, threshold=0.9):
        if threshold <= 0:
            return True
        elif threshold >= 1.0:
            return a == b

        if len(a) < len(b):
            a, b = b, a

        alen, blen = len(a), len(b)

        if blen == 0 or alen == 0:
            return alen == blen

        if blen == alen and a == b:
            return True

        len_ratio = float(blen) / alen

        if threshold > self.upper_bound_similarity(a, b):
            return False
        else:
            # Bad, we can't optimize anything here
            return threshold <= difflib.SequenceMatcher(None, a, b).quick_ratio()
    
    def upper_bound_similarity(self, a, b):
        return 2.0*(len(a))/(len(a)+len(b))

class CustomHttpService(IHttpService):
    def __init__(self, url):
        x = urlparse.urlparse(url)
        if x.scheme in ("http", "https"):
            self._protocol = x.scheme
        else:
            raise ValueError()
        self._host = x.hostname
        if not x.hostname:
            self._host = ""
        self._port = x.port
        if not self._port:
            if self._protocol == "http":
                self._port = 80
            elif self._protocol == "https":
                self._port = 443

    def getHost(self):
        return self._host

    def getPort(self):
        return self._port

    def getProtocol(self):
        return self._protocol

    def __str__(self):
        return CustomHttpService.to_url(self)

    @staticmethod
    def to_url(service):
        a = FloydsHelpers.u2s(service.getProtocol()) + "://" + FloydsHelpers.u2s(service.getHost())
        if service.getPort():
            a += ":" + str(service.getPort())
        return a + "/"


class CustomRequestResponse(IHttpRequestResponse):
    # Every call in the code to getRequest or getResponse must be followed by
    # callbacks.analyzeRequest or analyze Response OR
    # FloydsHelpers.jb2ps OR
    # another operation such as len()

    def __init__(self, comment, highlight, service, request, response):
        self.com = comment
        self.high = highlight
        self.setHttpService(service)
        self.setRequest(request)
        self.setResponse(response)

    def getComment(self):
        return self.com

    def getHighlight(self):
        return self.high

    def getHttpService(self):
        return self.serv

    def getRequest(self):
        return self.req

    def getResponse(self):
        return self.resp

    def setComment(self, comment):
        self.com = comment

    def setHighlight(self, color):
        self.high = color

    def setHttpService(self, httpService):
        if isinstance(httpService, str):
            self.serv = CustomHttpService(httpService)
        else:
            self.serv = httpService

    def setRequest(self, message):
        if isinstance(message, str):
            self.req = FloydsHelpers.ps2jb(message)
        else:
            self.req = message

    def setResponse(self, message):
        if isinstance(message, str):
            self.resp = FloydsHelpers.ps2jb(message)
        else:
            self.resp = message

    def serialize(self):
        # print type(self.com), type(self.high), type(CustomHttpService.to_url(self.serv)), type(self.req), type(self.resp)
        return self.com, self.high, CustomHttpService.to_url(self.serv), FloydsHelpers.jb2ps(self.req), FloydsHelpers.jb2ps(self.resp)

    def deserialize(self, serialized_object):
        self.com, self.high, service_url, self.req, self.resp = serialized_object
        self.req = FloydsHelpers.ps2jb(self.req)
        self.resp = FloydsHelpers.ps2jb(self.resp)
        self.serv = CustomHttpService(service_url)


#
# extend JTable to handle cell selection
#
    
class Table(JTable):

    def __init__(self, extender):
        self._extender = extender
        self.setModel(extender)
        return
    
    def changeSelection(self, row, col, toggle, extend):
    
        # show the log entry for the selected row
        logEntry = self._extender._log.get(row)
        self._extender._requestViewer.setMessage(logEntry._requestResponse.getRequest(), True)
        self._extender._responseViewer.setMessage(logEntry._requestResponse.getResponse(), False)
        self._extender._currentlyDisplayedItem = logEntry._requestResponse
        
        JTable.changeSelection(self, row, col, toggle, extend)
        return
    
#
# class to hold details of each log entry
#

class LogEntry:

    def __init__(self, tool, requestResponse, url):
        self._tool = tool
        self._requestResponse = requestResponse
        self._url = url
        return

class FloydsHelpers(object):
    
    @staticmethod
    def jb2ps(arr):
        """
        Turns Java byte arrays into Python str
        :param arr: [65, 65, 65]
        :return: 'AAA'
        """
        return ''.join(map(lambda x: chr(x % 256), arr))

    @staticmethod
    def ps2jb(arr):
        """
        Turns Python str into Java byte arrays
        :param arr: 'AAA'
        :return: [65, 65, 65]
        """
        return [ord(x) if ord(x) < 128 else ord(x) - 256 for x in arr]

    @staticmethod
    def u2s(uni):
        """
        Turns unicode into str/bytes. Burp might pass invalid Unicode (e.g. Intruder Bit Flipper).
        This seems to be the only way to say "give me the raw bytes"
        :param uni: u'https://example.org/invalid_unicode/\xc1'
        :return: 'https://example.org/invalid_unicode/\xc1'
        """
        if isinstance(uni, unicode):
            return uni.encode("iso-8859-1", "ignore")
        else:
            return uni

