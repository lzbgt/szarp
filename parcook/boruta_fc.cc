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

  Patryk Kulpanowski <pkulpanowski@newterm.pl>
*/

/*
 @description_start

 @class 4

 @devices This is a borutadmn subdriver for FC protocol, used by Danfoss Inverter VLT6000, Danfoss Inverter VLT5000
 @devices.pl Sterownik do demona borutadmn, obsługujący protokół FC, używany przez  Danfoss VLT6000, VLT5000.

 @protocol FC over RS485 (can be used over TCP/IP)
 @protocol.pl protokół FC poprzez port szeregowy RS485 (może być symulowane przez TCP/IP)

 @config Driver is configured as a unit subelement of device element in params.xml. See example for allowed attributes.
 @config.pl Sterownik jest konfigurowany w pliku params.xml, w podelemencie unit elementu device. Opis dodawnych atrybutów XML znajduje się w przykładzie poniżej.

 @config_example
<device
	daemon="/opt/szarp/bin/borutadmn"
	path="/dev/null"
		ignored, should be /dev/null
	>
	<unit
		id="1"
			given as single digit or letter
			interpreted as ASCII ('A' is 65, '1' is 49)
		type="1"
			ignored, should be 1
		subtype="1"
			ignored, should be 1
		bufsize="1"
			ignored, should be 1
		extra:proto="fc"
			protocol name, denoting boruta driver to use, should be "fc"
			for this driver
		extra:mode="client"
			unit working mode, this driver is used only as client
		extra:medium="serial"
			data transmission medium, may be "serial" or "tcp"
			for using serial as medium need 1 more attribute:
				extra:path="/dev/ttyS0"
			for using tcp as medium need 3 more attributes:
				extra:use_tcp_2_serial_proxy="yes"
				extra:tcp-address="192.168.1.150"
				extra:tcp-port="6969"
		extra:id="13"
			address of polling inverter (in range from 1 to 31)
		extra:speed="9600"
			optional serial port speed in bps (for medium "serial")
			default is 9600, allowed values are also 300, 600, 1200, 2400, 4800
		extra:parity="even"
			optional serial port parity (for medium "serial")
			default is none, other allowed values are odd and even
		extra:inter-unit-delay="100"
			optional delay time in ms between querying units under device
		>
		<param
			name="Falowniki:Wyciąg Lewy:Napięcie łącza DC"
			...
			extra:parameter-number="518"
				number of parameter you want to poll
				you can get it from documents of inverters
			extra:prec="0"
				conversion index of parameter you want to poll
				you can get it from documents of inverters
				if negative, enter the absolute value to prec
				e.g. if conversion index is -2 give prec="2" (not extra:!)
			extra:val_op="lsw"
				optional operator for converting long or float values to
				parameter values; SZARP holds parameters as 2 bytes integers
				with fixed precision; if val_op is not given, 4 bytes float or
				long value is simply converted to short integer (reflecting
				precision)
				you can also divide one values into 2 szarp parameters (called
				'combined parameters');	you need to configure these 2 parameters
				with the same parameter-number and precision, but one with
				extra:val_op="msw" (it will hold most significant word of value)
				second with extra:val_op="lsw"
			>
		</param>
	</unit>
</device>

 @config_example.pl
<device
	daemon="/opt/szarp/bin/borutadmn"
	path="/dev/null"
		ignorowany, zaleca się ustawienie /dev/null
	>
	<unit
		id="1"
			identyfikator, jeżeli jest literą lub pojedyńczą cyfrą
			to interpretowany jest jako znak ASCII (czyli 'A' to 65, '1' to 49)
		type="1"
			ignorowany, zaleca się ustawienie 1
		subtype="1"
			ignorowany, zaleca się ustawienie 1
		bufsize="1"
			ignorowany, zaleca się ustawienie 1
		extra:proto="fc"
			nazwa protokołu, używana przez Borutę do ustalenia używanego
			sterownika, dla tego sterownika musi być fc
		extra:mode="client"
			tryb pracy jednostki, ten sterownik działa tylko jako client
		extra:medium="serial"
			medium transmisyjne, może być serial albo tcp,
			w celu używania transmisji szeregowej należy dodać atrybut:
				extra:path="/dev/ttyS0"
					ścieżka do portu szeregowego
			w celu używania transmisji po ethernecie należy dodać atrybuty:
				extra:use_tcp_2_serial_proxy="yes"
					pozwolenie na komunikację szeregową poprzez tcp
				extra:tcp-ip="192.168.1.150"
					adres IP do którego się podłączamy
				extra:tcp-port="6969"
					port IP na który się połączymy
		extra:id="13"
			adres odpytywanego falownika (od 1 do 31), odczytywane z falownika
		extra:speed="9600"
			opcjonalna, prędkość portu szeregowego w bps (dla medium serial)
			domyślna jest 9600, dopuszczalne wartości 300, 600, 1200, 2400, 4800
		extra:parity="even"
			opcjonalna, parzystość portu (dla medium serial)
			domyślne jest none, dopuszczalne wartości odd, even
		extra:inter-unit-delay="100"
			opcjonalna, czas opóźnienia w ms między odpytywaniem jednostek w
			jednym urządzeniu
		>
		<param
			name="Falowniki:Wyciąg Lewy:Napięcie łącza DC"
			...
			extra:parameter-number="518"
				numer parametru, który chcesz odpytać
				numer uzyskasz z odpowiedniej dokumentacji falownika
			extra:prec="0"
				conversion index parametru, który chcesz odpytać
				uzyskasz to z odpowiedniej dokumentacji falownika
				jeśli ujemny, podaj wartość bezwzględną do atrybutu prec
				np. jeśli conversion index jest -2 podaj prec="2" (bez extra:!)
			extra:val_op="lsw"
				opcjolany operator pozwalająy na konwersję wartości
				typu float i long na wartości parametrów SZARP
				domyślnie wartości te zamieniane są na 2 bajtową reprezentację
				wartości w systemie SZARP bezpośrednio, jedynie z uwzględnieniem
				precyzji parametru w SZARP możliwe jest jednak przepisanie tych
				wartości do dwóch parametrów SZARP (tak zwane parametry
				'kombinowane') co pazwala na nietracenie precyzji i uwzglednianie
				większego zakresu
				w tym celu należy skonfigurować 2 parametry SZARP z takimi
				samymi parametrami dotyczącymi numeru parametru i jego precyzji
				przy czym jeden z nich powinien mieć extra:val_op="lsw" a
				drugi extra:val_op="msw"
				przyjmą wartości odpowiednio mniej i bardziej znaczącego słowa
				wartości parametru
			>
		</param>
	</unit>
</device>

 @description_end
*/

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdexcept>
#include <sstream>

#include <event.h>
#include <libgen.h>

#include <boost/lexical_cast.hpp>
#include <boost/tokenizer.hpp>

#include <libxml/parser.h>
#include <libxml/xpath.h>
#include <libxml/xpathInternals.h>

#include "liblog.h"
#include "xmlutils.h"
#include "conversion.h"
#include "ipchandler.h"
#include "tokens.h"
#include "borutadmn.h"

const char STE = 0x02;	// always 02 HEX
const char LGE = 0x0E;	// 14 bytes of telegram
const char AK = 0x1;	// AK=1 means read value data

namespace {
class fc_register
{
	/* Parameter number */
	unsigned short m_pnu;
	std::string m_val;
	time_t m_mod_time;
	driver_logger *m_log;
public:
	fc_register(unsigned short pnu, driver_logger *log) : m_pnu(pnu), m_log(log) {};
	unsigned short get_pnu() { return m_pnu; }
	void set_val(std::string& val);
	int get_val(double& value);
};

typedef std::map<unsigned char, fc_register *> FCRMAP;

class read_val_op
{
protected:
	fc_register *m_reg;
	double m_prec;
public:
	read_val_op(fc_register *reg, double prec) : m_reg(reg), m_prec(prec) {};
	virtual short val() = 0;
};

class short_read_val_op : public read_val_op
{
public:
	short_read_val_op(fc_register *reg, double prec) : read_val_op(reg, prec) {};
	virtual short val();
};

class long_read_val_op : public read_val_op
{
protected:
	bool m_lsw;
public:
	long_read_val_op(fc_register *reg, double prec, bool lsw) : read_val_op(reg, prec), m_lsw(lsw) {};
	virtual short val();
};

void fc_register::set_val(std::string& val)
{
	m_val = val;
}

int fc_register::get_val(double& value)
{
	char *endptr;

	errno = 0;
	const char *str = m_val.c_str();
	double val = strtod(str, &endptr);

	if ((errno == ERANGE && (val == LONG_MAX || val == LONG_MIN)) || (errno != 0 && val == 0)) {
		m_log->log(0, "Error in ascii to double conversion");
		return 1;
	}

	if (endptr == str) {
		m_log->log(0, "No value in string");
		return 1;
	}
	value = val;
	m_log->log(10, "fc_register::get_val value: %f", value);

	return 0;
}

short short_read_val_op::val()
{
	double val;
	if (m_reg->get_val(val))
		return SZARP_NO_DATA;

	return (short)(val * m_prec);
}

short long_read_val_op::val()
{
	double val;

	if (m_reg->get_val(val))
		return SZARP_NO_DATA;

	int v = (val * m_prec);
	return m_lsw ? (short)(v & 0xFFFF) : (short)(v >> 16);
}

} //namespace

class fc_proto_impl : public serial_client_driver
{
	unsigned char m_id;
	short *m_read;
	short *m_send;
	size_t m_read_count;
	size_t m_send_count;
	struct bufferevent *m_bufev;
	struct event m_read_timer;
	bool m_read_timer_started;

	size_t m_data_in_buffer;

	/* Address of Danfoss Inverter */
	char m_extra_id;

	int m_timeout;
	driver_logger m_log;

	/* Serial connection state */
	enum { IDLE, REQUEST, RESPONSE  } m_state;

	/* Vector containing telegram */
	std::vector<unsigned char> m_request_buffer;

	std::vector<unsigned char> m_buffer;

	/* Register of parameters under unit */
	FCRMAP m_registers;
	FCRMAP::iterator m_registers_iterator;

	/*  */
	std::vector<read_val_op *> m_read_operators;

	/* Function to create checksum byte (xor of all previous bytes) */
	char checksum (std::vector<unsigned char>& buffer);

	void finished_cycle();
	void next_request();
	void send_request();
	void make_read_request();
	int parse_frame();
	void to_parcook();
	bool read_line(struct bufferevent *bufev);
	int parse_pwe(std::vector<unsigned char>& val);

	void start_read_timer();
	void stop_read_timer();

protected:
	void driver_finished_job();
	void terminate_connection();
	struct event_base *get_event_base();

public:
	fc_proto_impl();
	virtual const char *driver_name() { return "fc_serial_client"; }
	virtual void starting_new_cycle();
	virtual void data_ready(struct bufferevent *bufev, int fd);
	virtual void connection_error(struct bufferevent *bufev);
	virtual int configure(TUnit *unit, xmlNodePtr node, short *read, short *send, serial_port_configuration& spc);
	virtual void scheduled(struct bufferevent *bufev, int fd);
	void read_timer_event();
	static void read_timer_callback(int fd, short event, void *fc_proto_impl);

};

fc_proto_impl::fc_proto_impl() : m_log(this), m_state(IDLE) {}

char fc_proto_impl::checksum (std::vector<unsigned char>& buffer)
{
	m_log.log(10, "checksum");
	char exor = 0x00;
	for (size_t i = 0; i < buffer.size(); i++)
		exor ^= buffer.at(i);
	return exor;
}

void fc_proto_impl::finished_cycle()
{
	m_log.log(10, "finished_cycle");
	to_parcook();
}

void fc_proto_impl::next_request()
{
	m_log.log(10, "next_request");
	switch (m_state) {
	case REQUEST:
		// TODO error?
		break;
	case RESPONSE:
		// TODO error?
		break;
	default:
		break;
	}

	m_registers_iterator++;
	if (m_registers_iterator == m_registers.end()) {
		m_log.log(7, "next_request, no more registers to query, driver finished job");
		m_state = IDLE;
		m_manager->driver_finished_job(this);
		return;
	}

	m_data_in_buffer = 0;
	send_request();
}

void fc_proto_impl::send_request()
{
	m_log.log(10, "send_request");
	m_buffer.clear();
	make_read_request();
	bufferevent_write(m_bufev, &m_request_buffer[0], m_request_buffer.size());
	m_state = REQUEST;
	start_read_timer();
}

void fc_proto_impl::make_read_request()
{
	m_log.log(10, "make_read_request");
	m_request_buffer.clear();
	fc_register *reg = m_registers_iterator->second;

	/* Telegram contains STE - LGE - ADR - PKE - IND - PWE - PCD - BCC */
	m_request_buffer.push_back(STE);
	m_request_buffer.push_back(LGE);
	m_request_buffer.push_back(m_extra_id);

	/* Creating PKE - AK + PNU */
	m_request_buffer.push_back(AK << 4 | ((reg->get_pnu() & 0x0f00) >> 8));
	m_request_buffer.push_back(reg->get_pnu() & 0x00ff);

	/* Expanding telegram to 14 bytes, IND - PWE - PCD */
	for (unsigned char i = m_request_buffer.size(); i <= LGE; i++) {
		m_request_buffer.push_back(0x00);
	}

	/* BCC is xor of every byte in request */
	m_request_buffer.push_back(checksum(m_request_buffer));
}

int fc_proto_impl::parse_frame()
{
	if (m_buffer.size() == 0) {
		m_log.log(0, "parse_frame error - received buffer is empty");
		return 1;
	}
	m_log.log(7, "parse_frame, length: %zu", m_buffer.size());

	/* First 5 bytes of buffer should be the same as request_buffer */
	for (size_t i = 0; i < m_buffer.size() - 11; i++) {
		if(m_buffer.at(i) != m_request_buffer.at(i)) {
			m_log.log(5, "parse_frame warning - received buffer is different from requested buffer at %zu byte", i);
		}
	}

	std::vector<unsigned char> pwe_chars;
	/* Next 4 bytes are values - PWEhigh - PWElow */
	for (unsigned char i = 7; i < 11; i++) {
		if (m_buffer.at(i) == 0)
			continue;
		pwe_chars.push_back(m_buffer[i]);
	}

	/* Convert octal char to int and set 4 bytes from PWE to register */
	int value = parse_pwe(pwe_chars);
	std::string string_value = std::to_string(value);
	m_registers_iterator->second->set_val(string_value);

	/* Next 2 bytes are PCD1 status word */
	unsigned char PCD1 = 0;
	for (unsigned int i = 11; i < 13; i++) {
		PCD1 = m_buffer.at(i);
		if (PCD1 != 0)
			m_log.log(2, "parse_frame warning - status word PCD1 (byte %d) is %X", i, PCD1);
	}

	/* Ignoring last bytes (output frequency, BCC) */
	return 0;
}

int fc_proto_impl::parse_pwe(std::vector<unsigned char>& pwe)
{
	int value_buffer;
	int value = 0;
	for (std::vector<unsigned char>::iterator it = pwe.begin(); it != pwe.end(); it++) {
		value_buffer = *it;
		value = (value << 8) | value_buffer;
	}
	return value;

}

void fc_proto_impl::to_parcook()
{
	m_log.log(10, "to_parcook, m_read_count: %zu", m_read_count);
	for (size_t i = 0; i < m_read_count; i++) {
		m_read[i] = m_read_operators[i]->val();
		m_log.log(9, "Parcook param #%zu set to %hu", i, m_read[i]);
	}
}

void fc_proto_impl::start_read_timer()
{
	struct timeval tv;
	tv.tv_sec = 10;
	tv.tv_usec = 0;
	evtimer_add(&m_read_timer, &tv);
}

void fc_proto_impl::stop_read_timer()
{
	event_del(&m_read_timer);
}

void fc_proto_impl::driver_finished_job()
{
	m_manager->driver_finished_job(this);
}

void fc_proto_impl::terminate_connection()
{
	m_manager->terminate_connection(this);
}

struct event_base *fc_proto_impl::get_event_base()
{
	return m_event_base;
}

int fc_proto_impl::configure(TUnit *unit, xmlNodePtr node, short *read, short *send, serial_port_configuration& spc)
{
	m_id = unit->GetId();
	m_read_count = unit->GetParamsCount();
	m_send_count = unit->GetSendParamsCount();
	m_read = read;
	m_send = send;

	xmlXPathContextPtr xp_ctx = xmlXPathNewContext(node->doc);
	xp_ctx->node = node;
	int ret = xmlXPathRegisterNs(xp_ctx, BAD_CAST "ipk", SC::S2U(IPK_NAMESPACE_STRING).c_str());
	assert(ret == 0);
	ret = xmlXPathRegisterNs(xp_ctx, BAD_CAST "extra", BAD_CAST IPKEXTRA_NAMESPACE_STRING);
	assert(ret == 0);

	std::string _extra_id;
	if (get_xml_extra_prop(node, "id", _extra_id)) {
		m_log.log(0, "Invalid or missing extra:id attribute in param element at line: %ld", xmlGetLineNo(node));
		return 1;
	}

	char *e;
	long l = strtol(_extra_id.c_str(), &e, 0);
	if (*e != 0 || l < 0 || l > 32) {
		m_log.log(0, "Invalid value of extra:id value %ld, expected value between 1 and 31 (line %ld)", l, xmlGetLineNo(node));
		return 1;
	}
	/* ADR is address + 128 */
	m_extra_id = l + 128;
	m_log.log(10, "configure _extra_id: %02X", m_extra_id);

	for(size_t i = 0; i < m_read_count; i++) {
		char *expr;
		if (asprintf(&expr, ".//ipk:param[position()=%zu]", i+1) == -1) {
			m_log.log(0, "Could not find parameters in borutadmn type FC protocol");
			free(expr);
			return 1;
		}
		xmlNodePtr pnode = uxmlXPathGetNode(BAD_CAST expr, xp_ctx, false);
		assert(pnode);
		free(expr);

		std::string _pnu;
		if (get_xml_extra_prop(pnode, "parameter-number", _pnu, false)) {
			m_log.log(0, "Invalid or missing extra:parameter-number attribute in param element at line %ld", xmlGetLineNo(pnode));
			return 1;
		}

		char *e;
		long int l = strtol(_pnu.c_str(), &e, 0);
		if (*e != 0) {
			m_log.log(0, "Invalid extra:parameter-number attribute value: %ld (line %ld)", l, xmlGetLineNo(pnode));
			return 1;
		}
		unsigned short pnu = l;
		m_log.log(10, "configure _pnu: %ld, pnu: %u", l, pnu);

		std::string _prec;
		if (get_xml_extra_prop(pnode, "prec", _prec, true)) {
			m_log.log(0, "Invalid extra:prec attribute in param element at line: %ld", xmlGetLineNo(pnode));
			return 1;
		}

		l = strtol(_prec.c_str(), &e, 0);
		if (*e != 0 || l < 0 || ( l > 2 && l != 74)) {
			m_log.log(0, "Invalid extra:prec attribute value: %ld (line %ld)", l, xmlGetLineNo(pnode));
			m_log.log(0, "If conversion-index is negative put it absolute value to prec attribute (not extra:prec)");
			return 1;
		}

		double prec = 0;
		if (l == 74) {
			prec = 3.4;
		}
		else {
			prec = pow10(l);
		}
		m_log.log(10, "configure extra:prec: %f", prec);

		std::string val_op;
		if (get_xml_extra_prop(pnode, "val_op", val_op, true)) {
			m_log.log(0, "Invalid val_op attribute in param element at line: %ld", xmlGetLineNo(pnode));
			return 1;
		}

		fc_register *reg = NULL;
		reg = new fc_register(pnu, &m_log);

		if (val_op.empty()) {
			if (m_registers.find(pnu) != m_registers.end()) {
				m_log.log(0, "Already configured register with extra:parameter-number (%hd) in param element at line: %ld", pnu, xmlGetLineNo(pnode));
				return 1;
			}
			m_registers[pnu] = reg;
			m_read_operators.push_back(new short_read_val_op(reg, prec));
		}
		else {
			if (m_registers.find(pnu) == m_registers.end()) {
				m_registers[pnu] = reg;
			}
			else {
				reg = m_registers[pnu];
			}

			if (val_op == "lsw") {
				m_read_operators.push_back(new long_read_val_op(reg, prec, true));
			}
			else if (val_op == "msw") {
				m_read_operators.push_back(new long_read_val_op(reg, prec, false));
			}
			else {
				m_log.log(0, "Unsupported extra:val_op attribute value - %s, line %ld", val_op.c_str(), xmlGetLineNo(pnode));
				return 1;
			}
		}
	}

	evtimer_set(&m_read_timer, read_timer_callback, this);
	event_base_set(get_event_base(), &m_read_timer);
	return 0;
}

void fc_proto_impl::scheduled(struct bufferevent *bufev, int fd)
{
	m_bufev = bufev;
	m_log.log(10, "scheduled");
	switch (m_state) {
	case IDLE:
		m_registers_iterator = m_registers.begin();
		send_request();
		break;
	case REQUEST:
	case RESPONSE:
		m_log.log(2, "New cycle before end of querying");
		break;
	default:
		m_log.log(2, "Unknown state, something went teribly wrong");
		assert(false);
		break;
	}
}

void fc_proto_impl::connection_error(struct bufferevent *bufev)
{
	m_log.log(10, "connection_error");
	m_state = IDLE;
	m_bufev = NULL;
	m_buffer.clear();
	stop_read_timer();
	m_manager->driver_finished_job(this);
}

void fc_proto_impl::starting_new_cycle()
{
	m_log.log(10, "starting_new_cycle");
}

void fc_proto_impl::data_ready(struct bufferevent *bufev, int fd)
{
	char c;

	switch (m_state) {
		case IDLE:
			m_log.log(2, "Got unrequested message, ignoring");
			while (bufferevent_read(bufev, &m_buffer.at(m_data_in_buffer), m_buffer.size()) != 0);
			break;
		case REQUEST:
			while (bufferevent_read(bufev, &c, 1) != 0) {
				/* STE is starting frame */
				if (c == STE)
					break;
			}
			if (c != STE) {
				m_log.log(8, "Start of frame not found, waiting");
				break;
			}
			m_buffer.push_back(c);
			stop_read_timer();
			m_state = RESPONSE;
		case RESPONSE:
			if(!read_line(bufev))
				return;
			parse_frame();
			next_request();
			break;
		default:
			break;
	}
}

bool fc_proto_impl::read_line(struct bufferevent *bufev)
{
	char c;
	size_t bs;

	while (bufferevent_read(bufev, &c, 1)) {
		bs = m_buffer.size();
		if (bs == 15) {
			/* Received 15 bytes - checking checksum */
			char cs = checksum(m_buffer);
			if (c == cs) {
				m_buffer.push_back(c);
				return true;
			}
			else {
				m_log.log(0, "read_line error - wrong received checksum");
				return false;
			}
		}
		m_buffer.push_back(c);
	}
	return false;
}

void fc_proto_impl::read_timer_event()
{
	m_log.log(2, "read_timer_event, state: %d, reg: %d", m_state, m_registers_iterator->first);
	next_request();
}

void fc_proto_impl::read_timer_callback(int fd, short event, void *client)
{
	fc_proto_impl *fc = (fc_proto_impl *) client;
	fc->m_log.log(10, "read_timer_callback");
	fc->read_timer_event();
}

serial_client_driver *create_fc_serial_client()
{
 	return new fc_proto_impl();
}

