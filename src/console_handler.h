#ifndef CONSOLE_HANDLER_H_
#define CONSOLE_HANDLER_H_

#include <string>

#include "singleton.h"

class CommandHandler : public singleton<CommandHandler>
{
public:
  void handle_command(std::string in);
};

#endif // !CONSOLE_HANDLER_H_