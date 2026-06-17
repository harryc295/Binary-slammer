#ifndef LOGGER_H_
#define LOGGER_H_

#include <string>
#include <cstdio>
#include <fstream>
#include <vector>

#include "singleton.h"
#include "app_dirs.h"

struct log_t
{
  std::string message{};
  std::string owner{};
};

class Logger: public singleton<Logger>
{
public:
  Logger()
  {
    open_logfile();

    time_t now = time(0);
    struct tm local_time{};
    char date_time[26]{};
#ifdef _WIN32
    localtime_s(&local_time, &now);
    asctime_s(date_time, sizeof(date_time), &local_time);
#else
    localtime_r(&now, &local_time);
    asctime_r(&local_time, date_time);
#endif
    log("Session started at " + std::string(date_time), "Session Manager", true);
  }

  ~Logger()
  {
    time_t now = time(0);
    struct tm local_time{};
    char date_time[26]{};
#ifdef _WIN32
    localtime_s(&local_time, &now);
    asctime_s(date_time, sizeof(date_time), &local_time);
#else
    localtime_r(&now, &local_time);
    asctime_r(&local_time, date_time);
#endif
    log("Session ended at " + std::string(date_time), "Session Manager", true);
  }

  void log(std::string message, std::string author = "Generic", bool noio = false)
  {
    if (!m_logfile.is_open()
      && !open_logfile()) {
      if (!noio)
        printf("[%s]: Unable send log, reason: Cannot open the logfile.\n", author.c_str());
      return;
    }

    if (!noio)
      printf("[%s]: %s\n", author.c_str(), message.c_str());
    m_logfile << "[" << author << "]: " << message << "\n";
    m_logs.push_back({ message, author });
  }

  std::vector<log_t> get_logs()
  {
    return this->m_logs;
  }

  /*
  * Clears the in-memory commands, not the logs inside the logfile
  */
  void clear_logs()
  {
    m_logs = std::vector<log_t>(0);
  }

private:
  std::vector<log_t> m_logs;
  std::ofstream m_logfile;

  bool open_logfile()
  {
    if (m_logfile.is_open())
      return true;
    
    m_logfile.open(bh_path("binaryhammer.log"));
    
    return m_logfile.is_open();
  }
};

#endif // !LOGGER_H_
