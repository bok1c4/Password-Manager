#ifndef PANE_INTERFACE_H
#define PANE_INTERFACE_H

#include <string>
class PaneInterface {
public:
  virtual void render() = 0;
  virtual void handle_input(std::string input) = 0;
  virtual ~PaneInterface() = default;
};

#endif
