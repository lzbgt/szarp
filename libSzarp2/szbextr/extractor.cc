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


  Library for extracting data from SzarpBase to other formats.
 
  Pawe� Pa�ucha <pawel@praterm.com.pl>
 
  $Id$
*/

#include "sz4/exceptions.h"
#include "szbextr/extr.h"

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#include <assert.h>
#include <libxslt/xsltutils.h>
#include <zip.h>
#include "conversion.h"
#include "liblog.h"
#include "sz4/base.h"
#include "sz4/util.h"

#define XSLT_DIR PREFIX"/resources/xslt"
#define CSV_XSLT "extr_csv.xsl"
#define OO_XSLT "extr_oo.xsl"

SzbExtractor::BaseAdapter::~BaseAdapter() {}

class Sz4BaseAdapter : public SzbExtractor::BaseAdapter {
	sz4::base* base;
public:
	Sz4BaseAdapter(sz4::base *base) : base(base) {}

	void NextQuery() {}

	double GetAverage(TParam* p, time_t start, time_t end, SZARP_PROBE_TYPE pt) {
		sz4::weighted_sum<double, sz4::second_time_t> sum;
		try {
			base->get_weighted_sum(p, sz4::second_time_t(start), sz4::second_time_t(end), pt, sum);
			return sz4::scale_value(sum.avg(), p);
		} catch (sz4::exception&) {
			return nan("");
		}
	}

	double GetData(TParam* p, time_t time, SZARP_PROBE_TYPE pt) {
		return GetAverage(p, time, szb_move_time(time, 1, pt, 0), pt);
	}

	time_t SearchFirst(TParam *p) {
		sz4::second_time_t t;
		base->get_first_time(p, t);
		if (sz4::time_trait<sz4::second_time_t>::is_valid(t))
			return t;
		else
			return -1;
	}

	time_t SearchLast(TParam *p) {
		sz4::second_time_t t;
		base->get_last_time(p, t);
		if (sz4::time_trait<sz4::second_time_t>::is_valid(t))
			return t;
		else
			return -1;
	}
};

class SzbaseAdapter : public SzbExtractor::BaseAdapter {
	Szbase *base;
public:
	SzbaseAdapter(Szbase* base) : base(base) {}

	void NextQuery() {
		base->NextQuery();
	}


	double GetAverage(TParam* p, time_t start, time_t end, SZARP_PROBE_TYPE pt) {
		szb_buffer_t* szb = base->GetBuffer(p->GetSzarpConfig()->GetPrefix());
		if (szb)
			return szb_get_avg(szb , p, start , end , NULL , NULL , pt );
		else
			return nan("");
	}

	double GetData(TParam* p, time_t time, SZARP_PROBE_TYPE pt) {
		szb_buffer_t* szb = base->GetBuffer(p->GetSzarpConfig()->GetPrefix());
		if (szb)
			return szb_get_data(szb, p, time);
		else
			return nan("");
	}

	time_t SearchFirst(TParam *p) {
		szb_buffer_t* szb = base->GetBuffer(p->GetSzarpConfig()->GetPrefix());
		if (!szb)
			return -1;
		else
			return szb_search_first(szb, p);
	}

	time_t SearchLast(TParam *p) {
		szb_buffer_t* szb = base->GetBuffer(p->GetSzarpConfig()->GetPrefix());
		if (!szb)
			return -1;
		else
			return szb_search_last(szb, p);
	}
};

SzbExtractor::SzbExtractor(IPKContainer* ipk, Szbase *szbase)
{
	assert (szbase != NULL);

	this->base = new SzbaseAdapter(szbase);
	this->ipk = ipk;
	
	Init();
}

SzbExtractor::SzbExtractor(IPKContainer* ipk, sz4::base *sz4)
{
	this->base = new Sz4BaseAdapter(sz4);
	this->ipk = ipk;

	Init();
}

void SzbExtractor::Init() {
	start = -1;
	end = -1;
	period_type = PT_MIN10;
	custom_period = 0;
	empty = 0;
	nodata_str = L"NO_DATA";
	progress_watcher = NULL;
	watcher_data = NULL;
	cancel_pointer = &private_zero;
	dec_sep = 0;
	private_zero = 0;
	priv_buffer[_SZBEXTRACTOR_PRIV_BUFFER_SIZE - 1] = 0;
}

SzbExtractor::~SzbExtractor()
{
	delete base;
}

SZBASE_TYPE SzbExtractor::get_probe( const Param& p , TParam*tp , time_t t , SZARP_PROBE_TYPE pt , int ct )
{
	time_t s = szb_round_time(t, pt, ct);
	time_t e = szb_move_time(s, 1, pt, ct);

	SZBASE_TYPE res = SZB_NODATA;
	
	switch( p.type  )
	{
	case TYPE_AVERAGE :
		res = base->GetAverage(tp, s, e, pt);
		break;
// Dosent work as expected
//        case TYPE_START :
//                break;
	case TYPE_END :
		res = base->GetData(tp, s, pt);
		break;

	case TYPE_START :
		time_t h = szb_round_time(t, PT_MIN10, ct);
		time_t n = szb_move_time(h, 12, PT_MIN10, ct);
		res = base->GetData(tp, n, PT_MIN10);
		break;
	}

	return res;
}

int SzbExtractor::SetParams(const std::vector<Param>& params)
{
	this->params = params;
	params_objects.clear();

	for (size_t i = 0; i < params.size(); i++) {
		TParam *p = ipk->GetParam(params[i].prefix + L":" + params[i].name);
		if ((p == NULL) || (!p->IsReadable()))
			return i + 1;
		params_objects.push_back(p);
	}
	return 0;
}

void SzbExtractor::SetPeriod(SZARP_PROBE_TYPE period_type,
		time_t start, time_t end, int custom_period)
{
	assert (start <= end);
	assert ( (period_type != PT_CUSTOM) || (custom_period > 0) );

	this->start = szb_round_time(start, period_type, custom_period);
	this->end = szb_round_time(end, period_type, custom_period);
	
	this->custom_period = custom_period;
	this->period_type = period_type;
}

void SzbExtractor::SetMonth(SZARP_PROBE_TYPE period_type,
		int year, int month, int custom_period)
{
	assert (year > 1970);
	assert (month >= 1);
	assert (month <= 12);
	start = probe2time(0, year, month);
	end = probe2time(szb_probecnt(year, month), year, month);
	start = szb_round_time(start, period_type, custom_period);
	end = szb_round_time(end, period_type, custom_period);
	this->period_type = period_type;
}

void SzbExtractor::SetEmpty(int empty)
{
	assert ((empty == 0) || (empty == 1));
	this->empty = empty;
}

void SzbExtractor::SetNoDataString(const std::wstring& str)
{
	nodata_str = str;
}

void SzbExtractor::SetProgressWatcher(void*(*watcher)(int, void*),
		void *data)
{
	progress_watcher = watcher;
	watcher_data = data;
}

void SzbExtractor::SetDecDelim(wchar_t dec_sep)
{
	this->dec_sep = dec_sep;
}

const char* SzbExtractor::SetFormat(SZARP_PROBE_TYPE period_type)
{
       	switch (period_type) {
		case PT_SEC10:
	    		return "%Y-%m-%d %H:%M:%S";
		case PT_CUSTOM :
		case PT_MIN10 :
		case PT_HOUR :
		case PT_HOUR8 :
	    		return "%Y-%m-%d %H:%M";
	    		break;
		case PT_DAY :
	    		return "%Y-%m-%d";
	    		break;
		case PT_WEEK :
	    		return "%Y Week %W";
	    		break;
		case PT_MONTH :
	    		return "%Y %B";
	    		break;
		case PT_YEAR :
	    		return "%Y";
	    		break;
		default:
	    		assert (0);
    	}
}

SzbExtractor::ErrorCode 
SzbExtractor::ExtractToCSV(FILE *output, const std::wstring& delimiter)
{
    int rc = -1;
    time_t t;
    struct tm tm;

#ifndef HAVE_LOCALTIME_R
    struct tm *ptm;
#endif
    
    int percent = 0, old_percent = -1;	// for progress watching
    
#define CHECK_RC \
    if (rc < 0) { printf ("internal problem!\n"); \
	return ERR_XMLWRITE; }
#define CHECK_CANCEL \
    if (*cancel_pointer) { \
	return ERR_CANCEL; \
    }

    base->NextQuery();
    
    CHECK_CANCEL
	
    fprintf(output, "Data");
    
    for (size_t i = 0; i < params_objects.size(); i++) {
	// parameter name
	rc = fprintf(output, "%s%s", SC::S2A(delimiter).c_str(), SC::S2L(params[i].name).c_str());
    }
    CHECK_RC
	
    // set time format
    const char *format = SetFormat(period_type);
    
    // buffer for date
#define BUF_SIZE 100
    
    char datebuf[BUF_SIZE];
    int dif = (end - start) / 100;
    
    for (t = start; t < end; t = szb_move_time(t, 1, period_type, custom_period)) {
	if (progress_watcher) {
	    percent = (t - start) / dif;
	    if (percent != old_percent) {
		old_percent = percent;
		progress_watcher(percent, watcher_data);
	    }
	}
	
	/* <time/> */
#ifndef HAVE_LOCALTIME_R
	ptm = localtime(&t);
	memcpy(&tm, ptm, sizeof (struct tm));
#else
	localtime_r(&t, &tm);
#endif
	strftime(datebuf, BUF_SIZE, format, &tm);
	
	int no_empty = 0; // 1 if no-empty value was in row
	int time_printed = 0;
	for (size_t i = 0; i < params_objects.size(); i++) {
	    CHECK_CANCEL

	    SZBASE_TYPE data
		= get_probe(params[i], params_objects[i], t, period_type, custom_period);

	    if (!empty && !no_empty) {
		/** print previous empty values */
		if (data != SZB_NODATA) {
		    /* print time */
		    if (!time_printed) {
			time_printed = 1;
			/* <row> */
			rc = fprintf(output, "\n");
			CHECK_RC;
			rc = fprintf(output, "%s", datebuf);
			CHECK_RC;
		    }
		    
		    no_empty = 1;
		    for (size_t j = 0; j < i; j++) {
			rc = fprintf(output, "%s", SC::S2A(delimiter).c_str());
			CHECK_RC;
			rc = PrintValueToFile(output, SZB_NODATA, params_objects[j]);
			CHECK_RC;
		    }
		    /* print current value */
		    rc = fprintf(output, "%s", SC::S2A(delimiter).c_str());
		    CHECK_RC;
		    rc = PrintValueToFile(output, data, params_objects[i]);
		    CHECK_RC;
		}
	    }
	    else {
		/* print time */
		if (!time_printed) {
		    time_printed = 1;
		    /* <row> */
		    rc = fprintf(output, "\n");
		    CHECK_RC;
		    rc = fprintf(output, "%s", datebuf);
		    CHECK_RC;
		}
		fprintf(output, "%s", SC::S2A(delimiter).c_str());
		rc = PrintValueToFile(output, data, params_objects[i]);
		CHECK_RC;
	    }
	}
    }

    return ERR_OK;
#undef CHECK_RC
#undef CHECK_CANCEL
}

SzbExtractor::ErrorCode 
SzbExtractor::ExtractSum(FILE *output, const std::wstring& delimiter)
{
	int rc = -1;
	time_t t;
	struct tm tm;

#ifndef HAVE_LOCALTIME_R
	struct tm *ptm;
#endif
    
    
#define CHECK_RC \
    if (rc < 0) { printf ("internal problem!\n"); \
	return ERR_XMLWRITE; }
#define CHECK_CANCEL \
    if (*cancel_pointer) { \
	return ERR_CANCEL; \
    }
	CHECK_CANCEL
		
	base->NextQuery();
		
	for (size_t i = 0; i < params.size(); i++) {
		// nazwa parametru
		rc = fprintf(output, "%s%s", SC::S2L(params[i].name).c_str(), SC::S2A(delimiter).c_str());
	}
	fprintf(output, "\n");
	CHECK_RC
		

        for (size_t i = 0; i < params.size(); i++) {
		CHECK_CANCEL
			
		SZBASE_TYPE sum = 0;
		for (t = start; t < end; t = szb_move_time(t, 1, period_type, custom_period)) {
			/* <time/> */
#ifndef HAVE_LOCALTIME_R
			ptm = localtime(&t);
			memcpy(&tm, ptm, sizeof (struct tm));
#else
			localtime_r(&t, &tm);
#endif
			SZBASE_TYPE data
				= get_probe(params[i], params_objects[i], t, period_type, custom_period);
			if (!IS_SZB_NODATA(data)) {
				sum += data;
			}
			CHECK_RC;
		}
		rc = PrintValueToFile(output, sum, params_objects[i]);
		fprintf(output, "%s", SC::S2A(delimiter).c_str());
	}
	fprintf(output, "\n");
	
	return ERR_OK;
#undef CHECK_RC
#undef CHECK_CANCEL
}

int
SzbExtractor::PrintHeaderToOOXML(FILE* output, int param_num)
{
	int ret = fprintf(output, "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
<office:document-content\n\
	xmlns:office=\"urn:oasis:names:tc:opendocument:xmlns:office:1.0\"\n\
	xmlns:style=\"urn:oasis:names:tc:opendocument:xmlns:style:1.0\"\n\
	xmlns:text=\"urn:oasis:names:tc:opendocument:xmlns:text:1.0\"\n\
	xmlns:table=\"urn:oasis:names:tc:opendocument:xmlns:table:1.0\"\n\
	xmlns:draw=\"urn:oasis:names:tc:opendocument:xmlns:drawing:1.0\"\n\
	xmlns:fo=\"urn:oasis:names:tc:opendocument:xmlns:xsl-fo-compatible:1.0\"\n\
	xmlns:xlink=\"http://www.w3.org/1999/xlink\"\n\
	xmlns:dc=\"http://purl.org/dc/elements/1.1/\"\n\
	xmlns:meta=\"urn:oasis:names:tc:opendocument:xmlns:meta:1.0\"\n\
	xmlns:number=\"urn:oasis:names:tc:opendocument:xmlns:datastyle:1.0\"\n\
	xmlns:presentation=\"urn:oasis:names:tc:opendocument:xmlns:presentation:1.0\"\n\
	xmlns:svg=\"urn:oasis:names:tc:opendocument:xmlns:svg-compatible:1.0\"\n\
	xmlns:chart=\"urn:oasis:names:tc:opendocument:xmlns:chart:1.0\"\n\
	xmlns:dr3d=\"urn:oasis:names:tc:opendocument:xmlns:dr3d:1.0\"\n\
	xmlns:math=\"http://www.w3.org/1998/Math/MathML\"\n\
	xmlns:form=\"urn:oasis:names:tc:opendocument:xmlns:form:1.0\"\n\
	xmlns:script=\"urn:oasis:names:tc:opendocument:xmlns:script:1.0\"\n\
	xmlns:ooo=\"http://openoffice.org/2004/office\"\n\
	xmlns:ooow=\"http://openoffice.org/2004/writer\"\n\
	xmlns:oooc=\"http://openoffice.org/2004/calc\"\n\
	xmlns:dom=\"http://www.w3.org/2001/xml-events\"\n\
	xmlns:xforms=\"http://www.w3.org/2002/xforms\"\n\
	xmlns:xsd=\"http://www.w3.org/2001/XMLSchema\"\n\
	xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\"\n\
	xmlns:rpt=\"http://openoffice.org/2005/report\"\n\
	xmlns:of=\"urn:oasis:names:tc:opendocument:xmlns:of:1.2\"\n\
	xmlns:rdfa=\"http://docs.oasis-open.org/opendocument/meta/rdfa#\"\n\
	xmlns:field=\"urn:openoffice:names:experimental:ooxml-odf-interop:xmlns:field:1.0\"\n\
	xmlns:formx=\"urn:openoffice:names:experimental:ooxml-odf-interop:xmlns:form:1.0\"\n\
	office:version=\"1.2\">\n\
	<office:script/>\n\
	<office:font-decls/>\n\
	<office:automatic-styles>\n\
		<style:style style:name=\"co1\" style:family=\"table-column\">\n\
			<style:table-columns-properties fo:break-before=\"auto\"/>\n\
		</style:style>\n\
		<style:style style:name=\"co2\" style:family=\"table-column\">\n\
			<style:table-columns-properties fo:break-before=\"auto\"/>\n\
		</style:style>\n\
		<style:style style:name=\"ro1\" style:family=\"table-row\">\n\
			<style:table-row-properties fo:break-before=\"auto\" style:use-optimal-row-height=\"true\"/>\n\
		</style:style>\n\
		<style:style style:name=\"ta1\" style:family=\"table\" style:master-page-name=\"Default\">\n\
				<style:table-properties table:display=\"true\" style:writing-mode=\"lr-tb\"/>\n\
		</style:style>\n\
		<number:date-style style:name=\"N50\" number:automatic-order=\"true\" number:format-source=\"language\">\n\
		<number:year number:style=\"long\"/>\n\
      		<number:text>-</number:text>\n\
		<number:month number:style=\"long\"/>\n\
		<number:text>-</number:text>\n\
		<number:day number:style=\"long\"/>\n\
		<number:text> </number:text>\n\
		<number:hours number:style=\"long\"/>\n\
		<number:text>:</number:text>\n\
		<number:minutes number:style=\"long\"/>\n\
	      </number:date-style>\n\
      	      <style:style style:name=\"ce1\" style:family=\"table-cell\" style:parent-style-name=\"Default\" style:data-style-name=\"N50\"/>\n\
      </office:automatic-styles>\n\
      <office:body>\n\
       <office:spreadsheet>\n\
             <table:calculation-settings table:case-sensitive=\"false\" table:automatic-find-labels=\"false\" table:use-regular-expressions=\"false\"/>\n\
	      <table:table table:name=\"Sheet1\" table:style-name=\"ta1\">\n\
	      <table:table-column table:style-name=\"co1\" table:default-cell-style-name=\"ce1\"/>\n\
	      <table:table-column table:style-name=\"co2\" table:default-cell-style-name=\"Default\" table:number-columns-repeated=\"%d\"/>", param_num);
	if (ret >= 0) {
		return ERR_OK;
	} else {
		return -1;
	}
}

int
SzbExtractor::PrintTimeToOOXML(FILE* output, char *datebuf,
		SZARP_PROBE_TYPE period)
{
	fprintf(output, "</table:table-row><table:table-row table:style-name=\"ro1\">");
	char *c;
	switch (period_type) {
		case PT_SEC10:
		case PT_CUSTOM :
		case PT_MIN10 :
		case PT_HOUR :
		case PT_HOUR8 :
			c = strchr(datebuf, ' ');
			*c = 'T';
			break;
		default:
			c = NULL;
	}
	if ((period_type != PT_WEEK) && (period_type != PT_MONTH)) {
		fprintf(output, "<table:table-cell office:value-type=\"date\" office:date-value=\"");
	       	fprintf(output, "%s", datebuf);
	       	fprintf(output, "\"><text:p>");
	       	fprintf(output, "%s", datebuf);
	} else {
		fprintf(output, "<table:table-cell><text:p>");
	       	fprintf(output, "%s", datebuf);
	}
	if (c)
		*c = ' ';
	fprintf(output, "</text:p></table:table-cell>\n");
	return 0;
}
	
int
SzbExtractor::PrintValueToOOXML(FILE* output, SZBASE_TYPE data,
		TParam *param, xmlDocPtr doc)
{
	int rc;
#define CHECK_RC \
	if (rc < 0) { \
		return -1; \
	}
	if ((data == SZB_NODATA) || (param->GetFirstValue())) {
		fprintf(output, "<table:table-cell><text:p>");
		rc = PrintValueToFile(output, data, param, true, doc);
		fprintf(output, "</text:p></table:table-cell>");
		return ERR_OK;
	}
	fprintf(output, "<table:table-cell office:value-type=\"float\" office:value=\"");
	/* little hack */
	char c = dec_sep;
	dec_sep = '.';
	rc = PrintValueToFile(output, data, param, true, doc);
	dec_sep = c;
	CHECK_RC;
	fprintf(output, "\"><text:p>");
	rc = PrintValueToFile(output, data, param, true, doc);
	CHECK_RC;
	fprintf(output, "</text:p></table:table-cell>\n");
#undef CHECK_RC
	return ERR_OK;
}
SzbExtractor::ErrorCode
SzbExtractor::ExtractToOOXML(FILE* output)
{
	int rc = -1;
	time_t t;
	struct tm tm;
	xmlDocPtr txml = xmlNewDoc(BAD_CAST "1.0");
#ifndef HAVE_LOCALTIME_R
	struct tm *ptm;
#endif
	int percent = 0, old_percent = -1;	/* for progress watching */
	
#define CHECK_RC \
	if (rc < 0) { \
		printf ("internal problem!\n"); \
		xmlFreeDoc(txml); \
		return ERR_XMLWRITE; \
	}
#define CHECK_CANCEL \
	if (*cancel_pointer) { \
		xmlFreeDoc(txml); \
		return ERR_CANCEL; \
	}
	
	CHECK_CANCEL

	base->NextQuery();
		
	/* document header */
	rc = PrintHeaderToOOXML(output, params.size());
	CHECK_RC
	/* first row */
	rc = fprintf(output, "<table:table-row table:style-name=\"ro1\"><table:table-cell table:style-name=\"Default\"/>\n");
	CHECK_RC
	for (size_t i = 0; i < params.size(); i++) {
		/* parameter name */
		xmlChar *name = xmlEncodeSpecialChars(txml, SC::S2U(params[i].name).c_str());
		rc = fprintf(output, "<table:table-cell><text:p>%s</text:p></table:table-cell>\n", name);
		xmlFree(name);
		CHECK_RC
	}
	
	/* set time format */
    	const char *format = SetFormat(period_type);
	/* buffer for date */
#define BUF_SIZE 100
	int dif = (end - start) / 100;

	for (t = start; t < end; 
			t = szb_move_time(t, 1, period_type, custom_period))
	{
		if (progress_watcher) {
			percent = (t - start) / dif;
			if (percent != old_percent) {
				old_percent = percent;
				progress_watcher(percent, watcher_data);
			}
		}

		/* <time/> */
#ifndef HAVE_LOCALTIME_R
		ptm = localtime(&t);
		memcpy(&tm, ptm, sizeof (struct tm));
#else
		localtime_r(&t, &tm);
#endif
		char datebuf[BUF_SIZE];
		strftime(datebuf, BUF_SIZE, format, &tm);
		std::basic_string<unsigned char> ud = SC::L2U(datebuf, true);

		int no_empty = 0; /* 1 if no-empty value was in row */
		int time_printed = 0;
		for (size_t i = 0; i < params.size(); i++) {
			CHECK_CANCEL
			
			SZBASE_TYPE data = get_probe(params[i], params_objects[i],
					t, period_type, custom_period);
			if (!empty && !no_empty) {
				/** print previous empty values */
				if (data != SZB_NODATA) {
					/* print time */
					if (!time_printed) {
						time_printed = 1;
						/* <row> */
						rc = PrintTimeToOOXML(output, (char*) ud.c_str(), period_type);
						CHECK_RC
					}
					
					no_empty = 1;
					for (size_t j = 0; j < i; j++) {
						rc = PrintValueToOOXML(output, SZB_NODATA,
								params_objects[i], txml);
						CHECK_RC;
					}
					/* print current value */
					rc = PrintValueToOOXML(output, data,
							params_objects[i], txml);
					CHECK_RC;
				}
			} else {
				/* print time */
				if (!time_printed) {
					time_printed = 1;
					/* <row> */
					rc = PrintTimeToOOXML(output, (char*) ud.c_str(), period_type);
					CHECK_RC;
				}
				rc = PrintValueToOOXML(output, data,
						params_objects[i], txml);
				CHECK_RC;
			}
		}
	}
	fprintf(output, "</table:table-row></table:table></office:spreadsheet></office:body></office:document-content>\n");
	CHECK_RC;
	return ERR_OK;
#undef CHECK_RC
#undef CHECK_CANCEL
}

SzbExtractor::ErrorCode 
SzbExtractor::ExtractToOpenOffice(const std::wstring& path)
{
	ErrorCode ret;

	FILE* tmp = tmpfile();
	if (tmp == NULL) {
		return ERR_SYSERR;
	}
	ret = ExtractToOOXML(tmp);
	if (ret < 0) {
		fclose(tmp);
		return ret;
	}

	if (progress_watcher)
		progress_watcher(102, watcher_data);
	
	int errorp;
	struct zip *ods = zip_open(SC::U2A(SC::S2U(path)).c_str(), ZIP_CREATE | ZIP_EXCL, &errorp);
	if (ods == NULL) {
		if (errorp == ZIP_ER_EXISTS) {
			/* file already exists, try to remove it; another aproach it to
			 * empty zip archive, but it halts the program under Windows... */
			if (unlink(SC::U2A(SC::S2U(path)).c_str()) != 0) {
				fclose(tmp);
				return ERR_ZIPCREATE;
			}
			/* re-try creating file */
			ods = zip_open(SC::U2A(SC::S2U(path)).c_str(), ZIP_CREATE | ZIP_EXCL, &errorp);
		}
	}
	if (ods == NULL) {
		fclose(tmp);
		return ERR_ZIPCREATE;
	}
	struct zip_source *s;
	s = zip_source_filep(ods, tmp, 0 /* start offset */, -1 /* all file */);
	if (zip_add(ods, "content.xml", s) < 0) {
		sz_log(0, "%s", zip_strerror(ods));
		zip_source_free(s);
		return ERR_ZIPADD;
	}

	const char* manifest = "\
<?xml version=\"1.0\" encoding=\"UTF-8\"?>\
<manifest:manifest xmlns:manifest=\"urn:oasis:names:tc:opendocument:xmlns:manifest:1.0\">\
 <manifest:file-entry manifest:media-type=\"application/vnd.oasis.opendocument.spreadsheet\" manifest:version=\"1.2\" manifest:full-path=\"/\"/>\
 <manifest:file-entry manifest:media-type=\"\" manifest:full-path=\"Configurations2/statusbar/\"/>\
 <manifest:file-entry manifest:media-type=\"\" manifest:full-path=\"Configurations2/accelerator/current.xml\"/>\
 <manifest:file-entry manifest:media-type=\"\" manifest:full-path=\"Configurations2/accelerator/\"/>\
 <manifest:file-entry manifest:media-type=\"\" manifest:full-path=\"Configurations2/floater/\"/>\
 <manifest:file-entry manifest:media-type=\"\" manifest:full-path=\"Configurations2/popupmenu/\"/>\
 <manifest:file-entry manifest:media-type=\"\" manifest:full-path=\"Configurations2/progressbar/\"/>\
 <manifest:file-entry manifest:media-type=\"\" manifest:full-path=\"Configurations2/menubar/\"/>\
 <manifest:file-entry manifest:media-type=\"\" manifest:full-path=\"Configurations2/toolbar/\"/>\
 <manifest:file-entry manifest:media-type=\"\" manifest:full-path=\"Configurations2/images/Bitmaps/\"/>\
 <manifest:file-entry manifest:media-type=\"\" manifest:full-path=\"Configurations2/images/\"/>\
 <manifest:file-entry manifest:media-type=\"application/vnd.sun.xml.ui.configuration\" manifest:full-path=\"Configurations2/\"/>\
 <manifest:file-entry manifest:media-type=\"text/xml\" manifest:full-path=\"content.xml\"/>\
 <manifest:file-entry manifest:media-type=\"text/xml\" manifest:full-path=\"styles.xml\"/>\
 <manifest:file-entry manifest:media-type=\"text/xml\" manifest:full-path=\"meta.xml\"/>\
 <manifest:file-entry manifest:media-type=\"\" manifest:full-path=\"Thumbnails/thumbnail.png\"/>\
 <manifest:file-entry manifest:media-type=\"\" manifest:full-path=\"Thumbnails/\"/>\
 <manifest:file-entry manifest:media-type=\"text/xml\" manifest:full-path=\"settings.xml\"/>\
</manifest:manifest>";

	s = zip_source_buffer(ods, manifest, strlen(manifest), 0 /* don't free buffer */);
	if (zip_add(ods, "META-INF/manifest.xml", s) < 0) {
		sz_log(0, "%s", zip_strerror(ods));
		zip_source_free(s);
		return ERR_ZIPADD;
	}

	if (zip_close(ods) != 0) {
		return ERR_ZIPCREATE;
	}

	/* show 'completed' status */
	if (progress_watcher)
		progress_watcher(104, watcher_data);
	
	return ERR_OK;
}

SzbExtractor::ErrorCode 
SzbExtractor::ExtractStartEndTime(TSzarpConfig *ipk,
				time_t& start_time, time_t& end_time,
				int& num_of_params)
{
	time_t tmp_time;
	int max =
	    ipk->GetParamsCount() + ipk->GetDefinedCount() +
	    ipk->GetDrawDefinableCount();

	num_of_params = 0;

	int i = 0;
	for (TParam *prm = ipk->GetFirstParam(); prm != NULL; prm = ipk->GetNextParam(prm)) {
		if (progress_watcher)
			progress_watcher(i++ * 100 / max, watcher_data);
		if (!prm->IsReadable())
			continue;

		tmp_time = base->SearchFirst(prm);
		if (tmp_time == (time_t) -1)
			continue;
		if (start_time == (time_t) -1 || start_time > tmp_time)
			start_time = tmp_time;

		tmp_time = base->SearchLast(prm);
		assert(tmp_time != (time_t) -1);
		if (end_time == (time_t) -1 || tmp_time > end_time)
			end_time = tmp_time;

		num_of_params++;
	}

	return ERR_OK;
}

SzbExtractor::ErrorCode 
SzbExtractor::ExtractAndTransform(FILE *output,
		xsltStylesheetPtr stylesheet, char *params[],
		const std::string& encoding )
{
	assert (output != NULL);
	assert (stylesheet != NULL);
	
	ErrorCode ret;

	xmlDocPtr doc = NULL;
	xmlTextWriterPtr writer;

	/* write to doc */
	writer = xmlNewTextWriterDoc(&doc, 0);
	if (writer == NULL) {
		return ERR_SYSERR;
	}
	xmlTextWriterSetIndent(writer, 1);

	ret =  ExtractToXMLWriter(writer, encoding.c_str());
	xmlFreeTextWriter(writer);
	if (ret == ERR_OK) {
		if (progress_watcher)
			progress_watcher(101, watcher_data);
		/* apply stylesheet */
		xmlDocPtr tr = xsltApplyStylesheet(stylesheet, doc, 
				(const char **)params);
		if (tr == NULL)
			ret = ERR_TRANSFORM;
		else {
			if (progress_watcher)
				progress_watcher(103, watcher_data);
			/* dump doc */
			if (xsltSaveResultToFile(output, tr, stylesheet) < 0) {
				ret = ERR_SYSERR;
			} else {
				ret = ERR_OK;
				if (progress_watcher)
					progress_watcher(104, watcher_data);
			}
			xmlFreeDoc(tr);
		}
	}
	if (doc != NULL)
		xmlFreeDoc(doc);
	return ret;
}

SzbExtractor::ErrorCode 
SzbExtractor::ExtractAndTransform(FILE *output, char *stylesheet_path,
		char *params[],
		const std::string& encoding )
{
	ErrorCode ret;
	xsltStylesheetPtr stylesheet;
	stylesheet = xsltParseStylesheetFile(SC::L2U(stylesheet_path).c_str());
	if (stylesheet == NULL)
		return ERR_LOADXSL;
	ret = ExtractAndTransform(output, stylesheet, params, encoding);
	xsltFreeStylesheet(stylesheet);
	return ret;
}

SzbExtractor::ErrorCode 
SzbExtractor::ExtractToXML(FILE *output, const std::string &encoding)
{
	assert (output != NULL);
	ErrorCode ret;

	xmlBufferPtr buf;
	xmlTextWriterPtr writer;

	buf = xmlBufferCreate();
	if (buf == NULL) {
		return ERR_SYSERR;
	}
	/* write to doc */
	writer = xmlNewTextWriterMemory(buf, 0);
	if (writer == NULL) {
		return ERR_SYSERR;
	}
	xmlTextWriterSetIndent(writer, 1);

	ret =  ExtractToXMLWriter(writer, encoding);
	xmlFreeTextWriter(writer);
	if (ret == ERR_OK) {
		if (progress_watcher)
			progress_watcher(103, watcher_data);
		/* dump doc */
		if (fprintf(output, "%s", (const char *)buf->content) < 0) {
			ret = ERR_SYSERR;
		} else {
			ret = ERR_OK;
			if (progress_watcher)
				progress_watcher(104, watcher_data);
		}
	}
	xmlBufferFree(buf);
	return ret;
}

SzbExtractor::ErrorCode 
SzbExtractor::ExtractToXMLWriter(xmlTextWriterPtr writer, const std::string& encoding)
{
    assert (writer != NULL);
    
    int rc;
    time_t t;
    struct tm tm;
#ifndef HAVE_LOCALTIME_R
    struct tm *ptm;
#endif
    int percent = 0, old_percent = -1;	// for progress watching
    
#define CHECK_RC \
    if (rc < 0) { printf ("internal problem!\n"); \
	return ERR_XMLWRITE; }
#define CHECK_CANCEL \
    if (*cancel_pointer) { \
	xmlTextWriterEndDocument(writer); \
	return ERR_CANCEL; \
    }
    
    CHECK_CANCEL
	    
    base->NextQuery();
    
    /* start document */
    rc = xmlTextWriterStartDocument(writer, NULL, encoding.c_str(), NULL);
    CHECK_RC;
    
    /* <extracted> */
    rc = xmlTextWriterStartElementNS(writer, 
			NULL, 
			BAD_CAST "extracted",
			BAD_CAST "http://www.praterm.com.pl/SZARP/extr");
    CHECK_RC;
    
    /* <header> */
    rc = xmlTextWriterStartElement(writer, BAD_CAST "header");
    CHECK_RC;
    
    for (size_t i = 0; i < params.size(); i++) {
	/* <param/> */
	rc = xmlTextWriterWriteElement(writer,
		BAD_CAST "param",
		SC::S2U(params[i].name).c_str());
	CHECK_RC;
    }
    
    /* </header> */
    rc = xmlTextWriterEndElement(writer);
    CHECK_RC;
    
    /* <data> */
    rc = xmlTextWriterStartElement(writer, BAD_CAST "data");
    CHECK_RC;
    
    /* set time format */
    const char *format = SetFormat(period_type);
    /* buffer for date */
#define BUF_SIZE 100
    char datebuf[BUF_SIZE];
    int dif = (end - start) / 100;
    
    for (t = start; t < end; 
	    t = szb_move_time(t, 1, period_type, custom_period))
    {
	if (progress_watcher) {
	    percent = (t - start) / dif;
	    if (percent != old_percent) {
		old_percent = percent;
		progress_watcher(percent, watcher_data);
	    }
	}
	
	/* <time/> */
#ifndef HAVE_LOCALTIME_R
	ptm = localtime(&t);
	memcpy(&tm, ptm, sizeof (struct tm));
#else
	localtime_r(&t, &tm);
#endif
	strftime(datebuf, BUF_SIZE, format, &tm);
	
	int no_empty = 0; /* 1 if no-empty value was in row */
	int time_printed = 0;
	for (size_t i = 0; i < params.size(); i++) {
	    CHECK_CANCEL;
	    
	    SZBASE_TYPE data = get_probe(params[i], params_objects[i],
		    t, period_type, custom_period);
	    if (!empty && !no_empty) {
		/** print previous empty values */
		if (data != SZB_NODATA) {
		    /* print time */
		    if (!time_printed) {
			time_printed = 1;
			/* <row> */
			rc = xmlTextWriterStartElement(writer, BAD_CAST "row");
			CHECK_RC;
			
			rc = xmlTextWriterWriteElement(writer, BAD_CAST "time",	SC::L2U(datebuf, true).c_str());
			CHECK_RC;
		    }

		    no_empty = 1;
		    for (size_t j = 0; j < i; j++) {
			rc = PrintValueToWriter(writer,	SZB_NODATA, params_objects[i]);
			CHECK_RC;
		    }
		    
		    /* print current value */
		    rc = PrintValueToWriter(writer, data, params_objects[i]);
		    CHECK_RC;
		}
	    }
	    else {
		/* print time */
		if (!time_printed) {
		    time_printed = 1;
		    /* <row> */
		    rc = xmlTextWriterStartElement(writer, BAD_CAST "row");
		    CHECK_RC;
		    
		    rc = xmlTextWriterWriteElement(writer, BAD_CAST "time", SC::L2U(datebuf, true).c_str());
		    CHECK_RC;
		}
		
		PrintValueToWriter(writer, data, params_objects[i]);
	    }
	}
	
	/* </row> */
	if (time_printed) {
	    rc = xmlTextWriterEndElement(writer);
	    CHECK_RC;
	}
    }
    
    /* </data> */
    rc = xmlTextWriterEndElement(writer);
    CHECK_RC;
    
    /* </extracted> */
    rc = xmlTextWriterEndElement(writer);
    CHECK_RC;
    
    /* end document */
    rc = xmlTextWriterEndDocument(writer);
    CHECK_RC;
    
    return ERR_OK;
#undef CHECK_RC
#undef CHECK_CANCEL
}

int SzbExtractor::PrintValueToWriter(xmlTextWriterPtr writer, SZBASE_TYPE data, TParam *p)
{
	p->PrintValue(priv_buffer, _SZBEXTRACTOR_PRIV_BUFFER_SIZE - 1, data, nodata_str.c_str());
	ReplaceSeparator(priv_buffer);
	return xmlTextWriterWriteElement(writer, BAD_CAST "value", SC::S2U(priv_buffer).c_str());
}

int SzbExtractor::PrintValueToFile(FILE *output,
	SZBASE_TYPE data, TParam *p, bool toutf8, xmlDocPtr doc)
{
	p->PrintValue(priv_buffer, _SZBEXTRACTOR_PRIV_BUFFER_SIZE - 1, data, nodata_str);
	ReplaceSeparator(priv_buffer);
	if (toutf8) {
	    assert (doc != NULL);
	    xmlChar *name = xmlEncodeSpecialChars(doc, SC::S2U(priv_buffer).c_str());
	    int ret =  fprintf(output, "%s", name);
	    xmlFree(name);
	    return ret;
	}
	else {
	    return fprintf(output, "%s", SC::S2A(priv_buffer).c_str());
	}
}

/*
int SzbExtractor::PrintValueToStream(wxOutputStream& output,
	SZBASE_TYPE data, TParam *p, bool toutf8, xmlDocPtr doc)
{
	p->PrintValue(priv_buffer, _SZBEXTRACTOR_PRIV_BUFFER_SIZE - 1, data, nodata_str);
	ReplaceSeparator(priv_buffer);
	if (toutf8) {
	    assert (doc != NULL);
	    xmlChar *name = xmlEncodeSpecialChars(doc, SC::S2U(priv_buffer).c_str());
	    sw(output, (const char *)name);
	    xmlFree(name);
	}
	else {
	    sw(output, SC::S2A(priv_buffer).c_str());
	}
	return 0;
}
*/
void SzbExtractor::SetCancelValue(int *cancel_pointer)
{
	if (cancel_pointer == NULL)
		this->cancel_pointer = &private_zero;
	else
		this->cancel_pointer = cancel_pointer;
}

void SzbExtractor::ReplaceSeparator(wchar_t *buf)
{
	wchar_t *c;
	if (dec_sep == 0) {
		return;
	}
	for (c = buf; *c; c++) {
		if ((*c == '.') || (*c == ',')) {
			*c = dec_sep;
		}
	}
}

