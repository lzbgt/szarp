#!/usr/bin/python
# -*- coding: utf-8 -*-

import sip
sip.setapi('QString', 2)

from PyQt4 import QtGui , QtCore

from libipk.params import Params
from libipk.plugins import Plugins

from .xml_view import XmlView
from .xml_diag import XmlDialog
from .plug_diag import PluginsDialog

from .utils import *

from .ui.main_win import Ui_MainWindow

class MainWindow( QtGui.QMainWindow , Ui_MainWindow ) :
	def __init__( self , plugins ) :
		QtGui.QMainWindow.__init__( self )
		self.setupUi( self )

		self.view_full = XmlView( 'params' , self.centralwidget )
		self.hlay_xml.addWidget( self.view_full )
		self.view_full.changedSig.connect( self.touch_params )
		self.view_full.runSig.connect( self.runOnNodes )
		self.view_full.showSig.connect( self.showOnNodes )

		self.view_result = XmlView( 'result' , self.centralwidget )
		self.view_result.showSig.connect( self.showOnNodes )

		self.hlay_xml.addWidget( self.view_result )

		self.params = None
		self.plugins = Plugins()
		self.plugins.load(plugins)

	def touch_params( self ) :
		if self.params != None : self.params.touch()

	def rlyClose( self ) :
		if self.params == None or self.params.close() :
			return True
		else :
			reply = QtGui.QMessageBox.question(self, 'Message',
				"Params not saved. Are you sure to quit?",
				QtGui.QMessageBox.Yes | QtGui.QMessageBox.No,
				QtGui.QMessageBox.No)

			if reply == QtGui.QMessageBox.Yes:
				return True
			else :
				return False

	def closeEvent(self, event):
		if self.rlyClose() :
			event.accept()
		else :
			event.ignore()

	def save( self ) :
		if self.params != None :
			self.params.save()

	def saveAs( self ) :
		fn = QtGui.QFileDialog.getSaveFileNameAndFilter( self , 
				'Save File' , '.' ,
				'XML Files (*.xml);;All (*)' )

		if fn[0] != '' and self.params != None :
			self.params.save( fromUtf8(fn[0]) )

	def openParamsDialog( self ) :
		fn = QtGui.QFileDialog.getOpenFileNameAndFilter( self ,
				'Open File' , '.' ,
				'XML Files (*.xml);;All (*)' )

		if fn[0] != '' :
			self.openParams( fromUtf8(fn[0]) )

	def openParams( self , filename ) :
		self.params = Params( filename )
		self.view_full.clear()
		self.view_result.clear()
		self.view_full.add_node( self.params.root )

	def runOnNodes( self , nodes ) :
		result = self.openRunDialog()
		if result == None : return

		plug = self.plugins.get( result[0] , result[1] )

		self.view_result.clear()

		for n in nodes :
			plug.process( n )
			res_nodes = plug.result()
			for r in res_nodes :
				self.view_result.add_node( r )

	def showOnNodes( self , nodes ) :
		diag = XmlDialog( self )
		diag.add_nodes( nodes )
		diag.exec_()

	def openRunDialog( self ) :
		diag = PluginsDialog( self , self.plugins )
		if diag.exec_() == QtGui.QDialog.Accepted :
			return ( diag.selected_name() , diag.selected_args() )
		return None
