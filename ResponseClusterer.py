from burp import IBurpExtender
from burp import ITab
from burp import IHttpListener
from burp import IMessageEditorController
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
        callbacks.setExtensionName("ResponseClusterer")
        
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
        
        
        self.max_clusters = 200
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
        
        #clusters will grow up to self.max_clusters response bodies...
        self._clusters = set()        
        self.Similarity = Similarity()
        
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
        return "ResponseClusterer"
    
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
            iResponseInfo = self._helpers.analyzeResponse(resp)
            req = messageInfo.getRequest()
            iRequestInfo = self._helpers.analyzeRequest(messageInfo)
            mime_type = iResponseInfo.getStatedMimeType()
            if len(resp) >= self.response_max_size:
                #print "Message was too long"
                return
            if mime_type in self.uninteresting_mime_types:
                #print "Mime type", mime_type, "is ignored"
                return
            if iResponseInfo.getStatusCode() in self.uninteresting_status_codes:
                #print "Status code", iResponseInfo.getStatusCode(), "is ignored"
                return
            if '.' in iRequestInfo.getUrl().getFile() and iRequestInfo.getUrl().getFile().split('.')[-1] in self.uninteresting_url_file_extensions:
                #print iRequestInfo.getUrl().getFile().split('.')[-1], "is an ignored file extension"
                return
            if not self._callbacks.isInScope(iRequestInfo.getUrl()):
                #print iRequestInfo.getUrl(), "is not in scope"
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
                self._clusters.add((iResponseInfo.getStatusCode(), body))
                # create a new log entry with the message details
                row = self._log.size()
                self._log.add(LogEntry(toolFlag, self._callbacks.saveBuffersToTempFiles(messageInfo), iRequestInfo.getUrl()))
                self.fireTableRowsInserted(row, row)
            taken_time = time.time() - start_time
            if taken_time > 0.5:
                print "Performance problems: Plugin took", taken_time, "seconds to process request"
            self._lock.release()

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
      