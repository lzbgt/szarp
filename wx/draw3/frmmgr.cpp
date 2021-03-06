/* 
  SZARP: SCADA software 
  

  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; either version 2 of the License, or
  (at your option) any later version.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with this program; if not, write to the Free Software
  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA
*/
#include <utility>

#include <deque>

#include <wx/config.h>

#include "config.h"

#include "szhlpctrl.h"

#include "szframe.h"

#include "ids.h"
#include "classes.h"
#include "drawobs.h"

#include "drawtime.h"
#include "coobs.h"
#include "sprecivedevnt.h"
#include "parameditctrl.h"
#include "seteditctrl.h"
#include "remarks.h"
#include "drawpick.h"
#include "dbinquirer.h"
#include "drawfrm.h"
#include "frmmgr.h"
#include "dbmgr.h"
#include "drawapp.h"
#include "cfgdlg.h"
#include "cfgmgr.h"
#include "defcfg.h"
#include "dbinquirer.h"
#include "database.h"
#include "draw.h"
#include "xydiag.h"
#include "xygraph.h"
#include "xyzgraph.h"
#include "drawdnd.h"
#include "statdiag.h"
#include "drawpnl.h"

BEGIN_EVENT_TABLE(FrameManager, wxEvtHandler)
	LOG_EVT_CLOSE(FrameManager , OnClose, "frmmgr:close" )
END_EVENT_TABLE()

FrameManager::FrameManager(DatabaseManager *dmgr, ConfigManager *cfgmgr, RemarksHandler *rhandle) :
	database_manager(dmgr),
	config_manager(cfgmgr),
	remarks_handler(rhandle),
	remarks_frame(NULL),
	free_frame_number(first_frame_id)
{
}

bool FrameManager::CreateFrame(const wxString &prefix, const wxString& set, PeriodType pt, time_t time, const wxSize& size, const wxPoint &position, int selected_draw, bool try_load_layout, bool full_screen) {
	DrawFrame *frame = new DrawFrame(this, database_manager, config_manager, remarks_handler, NULL, free_frame_number, _T(""), prefix);

	if(!(try_load_layout && frame->LoadLayout())) {
		if (!frame->AddDrawPanel(prefix, set, pt, time, selected_draw)) {
			frame->Destroy();
			return false;
		}
	}

	frames.Add(frame);

	int fn = free_frame_number;

	int width, height;
	if (size.IsFullySpecified()) {
		width = size.GetWidth();
		height = size.GetHeight();
	} else {
		width = wxConfig::Get()->Read(wxString::Format(_T("DrawFrameWidth_%d"), fn), 850);
		height = wxConfig::Get()->Read(wxString::Format(_T("DrawFrameHeight_%d"), fn), 600);
	}

	int x,y;
	if (position.x != -1 && position.y != -1) {
		x = position.x;
		y = position.y;
	} else {
		x = wxConfig::Get()->Read(wxString::Format(_T("DrawFrameX_%d"), fn), 0L);
		y = wxConfig::Get()->Read(wxString::Format(_T("DrawFrameY_%d"), fn), 0L);
	}

	frame->SetSize(width, height);
	frame->SetPosition(wxPoint(x, y));

	if (free_frame_number == std::numeric_limits<int>::max())
		free_frame_number = 0;
	else
		free_frame_number++;

	if (full_screen)
		frame->SwitchFullScreen();

	frame->Show(true);
	frame->Raise();
	return true;

}

bool FrameManager::OpenInExistingFrame(const wxString &prefix, const wxString& set, PeriodType pt, time_t time, int selected_draw) {
	if (frames.GetCount() == 0) {
		bool ret = CreateFrame(prefix, set, pt, time, wxDefaultSize, wxDefaultPosition, selected_draw);
		if (ret) {
			frames[0]->Show(true);
			frames[0]->Raise();
		}
		return ret;
	}
	DrawFrame* frame = frames[0];
	DrawPanel* panel = frame->GetCurrentPanel();
	if (panel)
		panel->Switch(set, prefix, time, pt, selected_draw);
	else
		frame->AddDrawPanel(prefix, set, pt, time, selected_draw);
	frame->Show(true);
	frame->Raise();
	return true;
}

void FrameManager::OnClose(wxCloseEvent &event) {
	DrawFrame *frame = wxDynamicCast(event.GetEventObject(), DrawFrame);
	assert(frame != NULL);

	if (event.CanVeto()) {
		wxString msg;

		if (frames.Count() == 1) {
			msg = _("Do you want to close the application?");

		} else
			msg = _("Do you want to close this window?");

		int ret = wxMessageBox(msg, _("Question"), wxYES_NO, frame);
		if (ret != wxYES) {
			event.Veto();
			return;
		}
	}

	size_t i;
	for (i = 0; i < frames.Count(); ++i)
		if (frames[i] == frame)
			break;

	assert(i < frames.Count());

	int dn = frame->wxWindowBase::GetId();

	int width, height;
	frame->GetSize(&width, &height);
	wxConfig::Get()->Write(wxString::Format(_T("DrawFrameWidth_%d"), dn), width);
	wxConfig::Get()->Write(wxString::Format(_T("DrawFrameHeight_%d"), dn), height);

	int x, y;
	frame->GetPosition(&x, &y);
	wxConfig::Get()->Write(wxString::Format(_T("DrawFrameX_%d"), dn), x);
	wxConfig::Get()->Write(wxString::Format(_T("DrawFrameY_%d"), dn), y);

	frame->SaveLayout();

	frame->Destroy();
	frames.RemoveAt(i);

	if (frames.Count() == 0) {
		wxConfig::Get()->Flush();
		wxExit();
	}

}

DrawFrame *FrameManager::FindFrame(int number) {
	DrawFrame *ret = NULL;

	for (size_t i = 0; i < frames.Count(); ++i)
		if (frames[i]->wxWindowBase::GetId() == number) {
			ret = frames[i];
			break;	
		}

	return ret;

}

void FrameManager::CreateXYGraph(wxString prefix,TimeInfo time, DrawInfoList user_draws) {
	DrawsSets* config = config_manager->GetConfigByPrefix(prefix);
	new XYFrame(config->GetID(), database_manager, config_manager, remarks_handler, time, user_draws, this);
}

void FrameManager::CreateXYZGraph(wxString prefix, TimeInfo time, DrawInfoList user_draws) {
	DrawsSets* config = config_manager->GetConfigByPrefix(prefix);
	new XYZFrame(config->GetID(), database_manager, config_manager, remarks_handler, time, user_draws, this);
}

void FrameManager::ShowStatDialog(wxString prefix, TimeInfo time, DrawInfoList user_draws) {
	DrawsSets* config = config_manager->GetConfigByPrefix(prefix);
	new StatDialog(NULL, config->GetID(), database_manager, config_manager, remarks_handler, time, user_draws);
}

void FrameManager::LoadConfig(DrawFrame *frame) {
	ConfigDialog *config_dialog = new ConfigDialog(frame, config_manager->GetConfigTitles(), DefinedDrawsSets::DEF_PREFIX);

	int ret = config_dialog->ShowModal();
	if (ret != wxID_OK) {
		config_dialog->Destroy();
		return;
	}

	wxString prefix = config_dialog->GetSelectedPrefix();

	if (prefix == DefinedDrawsSets::DEF_PREFIX) {
		DrawsSets *cfg = config_manager->GetConfigByPrefix(prefix);
		if (cfg == NULL || cfg->GetDrawsSets().size() == 0) {
			int ret = wxMessageBox(_("The are no user defined sets. Do you want to create one?"), _("Question"), wxICON_QUESTION | wxOK | wxCANCEL, frame);
			if (ret == wxOK)  {
				DrawPicker* dp = new DrawPicker(frame, config_manager, database_manager, remarks_handler);
				if (dp->NewSet(prefix, false) == wxID_OK)
					frame->AddDrawPanel(prefix, wxEmptyString, PERIOD_T_YEAR, 0);
				dp->Destroy();
			}
			config_dialog->Destroy();
			return;
		}
	}

	if (frame)
		frame->AddDrawPanel(prefix, wxEmptyString, PERIOD_T_YEAR, 0);
	else
		CreateFrame(prefix, wxEmptyString, PERIOD_T_YEAR, time_t(-1), wxDefaultSize, wxDefaultPosition);
	config_dialog->Destroy();
}

