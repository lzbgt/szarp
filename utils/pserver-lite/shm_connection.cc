#include "shm_connection.h"

#include <boost/lexical_cast.hpp>
#include <memory>

#include "liblog.h"
#include "libpar.h"
#include "ipcdefines.h"
#include "conversion.h"
#include "szarp_config.h"
#include "szbdefines.h"

volatile sig_atomic_t g_signals_blocked = 0;
volatile sig_atomic_t g_should_exit = 0;

RETSIGTYPE g_CriticalHandler(int signum)
{
	signal(signum, SIG_DFL);
	raise(signum);
}

RETSIGTYPE g_TerminateHandler(int signum)
{
	if (g_signals_blocked) {
		g_should_exit = 1;
	} else {
		signal(signum, SIG_DFL);
		raise(signum);
	}
}

ShmConnection::ShmConnection() 
: shm_desc(0), sem_desc(0), values_count(0)
{
}

ShmConnection::~ShmConnection()
{
}

void ShmConnection::register_signals()
{
	int ret;
	struct sigaction sa;
	sigset_t block_mask;
	
	sigfillset(&block_mask);
	sigdelset(&block_mask, SIGKILL);
	sigdelset(&block_mask, SIGSTOP);
	/* set no-cleanup handlers for critical signals */
	sa.sa_handler = g_CriticalHandler;
	sa.sa_mask = block_mask;
	sa.sa_flags = 0;
	ret = sigaction(SIGFPE, &sa, NULL);
	assert (ret == 0);
	ret = sigaction(SIGQUIT, &sa, NULL);
	assert (ret == 0);
	ret = sigaction(SIGILL, &sa, NULL);
	assert (ret == 0);
	ret = sigaction(SIGSEGV, &sa, NULL);
	assert (ret == 0);
	ret = sigaction(SIGBUS, &sa, NULL);
	assert (ret == 0);
	/* cleanup handlers for termination signals */
	sa.sa_handler = g_TerminateHandler;
	sa.sa_flags = SA_RESTART;
	ret = sigaction(SIGTERM, &sa, NULL);
	assert (ret == 0);
	ret = sigaction(SIGINT, &sa, NULL);
	assert (ret == 0);
	ret = sigaction(SIGHUP, &sa, NULL);
	assert (ret == 0);
}

bool ShmConnection::configure()
{
	std::wstring ipk_path;	

	libpar_init_with_filename("/etc/" PACKAGE_NAME "/" PACKAGE_NAME ".cfg", 1);

	char *config_param = libpar_getpar("global", "IPK", 0);
	if (config_param == nullptr) {
		sz_log(0, "TWriter::LoadConfig(): set 'IPK' param in szarp.cfg file");
		libpar_done();
		return false;
	} else {
		ipk_path = SC::L2S(config_param);
		free(config_param);
	}

	config_param = libpar_getpar("global", "parcook_path", 0);
	if (config_param == nullptr) {
		sz_log(0, "ShmConnection::configure(): set 'parcook_path' param in szarp.cfg file");
		libpar_done();
		return false;
	} else {
		parcook_path = std::string(config_param);
		free(config_param);
	}

	config_param = libpar_getpar("", "probes_buffer_size", 0);
	if (config_param != nullptr) {
		values_count = boost::lexical_cast<int>(config_param);
		free(config_param);
		sz_log(9, "ShmConnection::configure(): buffer size %d detected in szarp.cfg file", values_count);
	}
	
	libpar_done();

	std::unique_ptr<TSzarpConfig> config(new TSzarpConfig());

	xmlInitParser();

	if (config->loadXML(ipk_path) != 0) {
		sz_log(0, "ShmConnection::configure(): error loading configuration from file %s",
				SC::S2A(ipk_path).c_str());
		xmlCleanupParser();
		return false;
	}
	sz_log(5, "ShmConnection::configure(): IPK file %s successfully loaded", SC::S2A(ipk_path).c_str());
	
	params_count = config->GetParamsCount() + config->GetDefinedCount();

	xmlCleanupParser();

	return true;
}

bool ShmConnection::connect()
{
	key_t shm_key;
	key_t sem_key;
	const int max_attempts_no = 60;
	
	shm_segment.resize(values_count * params_count + SHM_PROBES_BUF_DATA_OFF);

	shm_key = ftok(parcook_path.c_str(), SHM_PROBES_BUF);
	if (shm_key == -1) {
		sz_log(0, "ShmConnection::connect(): ftok() for shm failed, errno %d, path '%s'",
			errno, parcook_path.c_str());
		return false;
	}

	sem_key = ftok(parcook_path.c_str(), SEM_PARCOOK);
	if (sem_key == -1) {
		sz_log(0, "ShmConnection::connect(): ftok() for sem failed, errno %d, path '%s'",
				errno, parcook_path.c_str());
		return false;
	}

	shm_desc = shmget(shm_key, 1, 00600);
	sem_desc = semget(sem_key, 2, 00600);
	for (int i = 0; ((shm_desc == -1) || (sem_desc == -1)) && (i < max_attempts_no-1); ++i)
	{
		sleep(1);
		shm_desc = shmget(shm_key, 1, 00600);
		sem_desc = semget(sem_key, 2, 00600);
	}

	if (shm_desc == -1) {
		sz_log(0, "ShmConnection::connect(): error getting shm id, errno %d, key %d", 
				errno, shm_key);
		return false;
	}
	if (sem_desc == -1) {
		sz_log(0, "ShmConnection::connect(): error getting semid, errno %d, key %d",
				errno, sem_key);
		return false;
	}

	return true;
}

void ShmConnection::shm_open(struct sembuf* semaphores)
{
	semaphores[0].sem_num = SEM_PROBES_BUF;
	semaphores[0].sem_op = 0;
	semaphores[0].sem_flg = SEM_UNDO;
	semaphores[1].sem_num = SEM_PROBES_BUF + 1;
	semaphores[1].sem_op = 1;
	semaphores[1].sem_flg = SEM_UNDO;

	if (semop(sem_desc, semaphores, 2) == -1) {
		sz_log(0, "ShmConnection:shm_open(): cannot open semaphore, errno %d, exiting", errno);
		g_signals_blocked = 0;
		/* we use non-existing signal '0' */
		g_TerminateHandler(0);
	}
}

void ShmConnection::shm_close(struct sembuf* semaphores)
{
	semaphores[0].sem_num = SEM_PROBES_BUF + 1;
	semaphores[0].sem_op = -1;
	semaphores[0].sem_flg = SEM_UNDO;
	if (semop(sem_desc, semaphores, 1) == -1) {
		sz_log(0, "ShmConnection:shm_close: cannot release semaphore, errno %d, exiting", errno);
		g_signals_blocked = 0;
		/* we use non-existing signal '0' */
		g_TerminateHandler(0);
	}
}

void ShmConnection::attach(int16_t** segment) 
{	
	do { 
		*segment = (int16_t*)shmat(shm_desc, 0, SHM_RDONLY); 

	} while((*segment == (void*)-1) && errno == EINTR);

	if (*segment != (void*)-1) return;

	sz_log(0, "ShmConnection:update_segment(): cannot attach segment, errno %d, exiting", errno);
	g_signals_blocked = 0;
	g_TerminateHandler(0);
}

void ShmConnection::detach(int16_t** segment) 
{
	if (shmdt(*segment) != -1) return;

	sz_log(0, "ShmConnection::update_segment(): cannot detache segment, errno %d, exiting", errno);
	g_signals_blocked = 0;
	g_TerminateHandler(0);
}

void ShmConnection::update_segment()
{
	int16_t* attached_segment = nullptr;
	struct sembuf semaphores[2];	

	g_signals_blocked = 1;
	
	shm_open(semaphores);
	attach(&attached_segment);
	
	std::copy(attached_segment, attached_segment + shm_segment.size(), shm_segment.begin());

	detach(&attached_segment);
	shm_close(semaphores);

	g_signals_blocked = 0;

	if (g_should_exit) 
		g_TerminateHandler(0);
}

std::vector<int16_t> ShmConnection::get_values(int param_index)
{
	std::vector<int16_t> param_values(values_count, SZB_FILE_NODATA);

	int16_t count = shm_segment[SHM_PROBES_BUF_CNT_INDEX]; 				
	int16_t pos = shm_segment[SHM_PROBES_BUF_POS_INDEX]; 				
				
	std::vector<int16_t>::iterator data = shm_segment.begin() + SHM_PROBES_BUF_DATA_OFF;

	int param_off = values_count * param_index;
	int param_end_off = param_off + values_count - 1;
	int pos_abs = pos + param_off;

	if (count < values_count) {
		std::copy(data + param_off, data + param_off + pos,  param_values.begin());
		return param_values;
	} else {
		int old_vals_cnt = param_end_off - pos_abs + 1;
		std::copy(data + pos_abs, data + pos_abs + old_vals_cnt, param_values.begin());
		if (pos == 0) return param_values;
		std::copy(data + param_off, data + param_off + pos, param_values.begin() + old_vals_cnt);
		return param_values;
	}
}
