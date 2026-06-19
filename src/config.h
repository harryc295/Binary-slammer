#ifndef _CONFIG_H_
#define _CONFIG_H_

#include "singleton.h"
#include "logger.h"
#include "app_dirs.h"
#include <filesystem>

#include <fstream>

class Config : public singleton<Config>
{
public:
  Config() {
    open_config();
  }

  bool open_config(bool guard = false)
  {
    std::ifstream in(bh_path("config.json"));
    if (!in.is_open()) {
      Logger::get()->log("Warn: Unable to open the include file", "Config");
      if (!create_config())
        return false;
    }
    return true;
  }

  bool create_config()
  {
    std::ofstream out(bh_path("config.json"));
    if (!out.is_open()) {
      Logger::get()->log("Fatal Error: Unable to create or access the config file.", "Config");
      throw 1;
    }

    return true;
  }
};

#endif // !_CONFIG_H_
