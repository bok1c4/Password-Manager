#ifndef VIEW_PWS_H
#define VIEW_PWS_H

#include "PaneInterface.h"

class ViewPwPane : public PaneInterface {
public:
  void render() override;
  void handle_input(char c) override;
};

#endif
