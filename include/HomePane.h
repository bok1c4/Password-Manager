#ifndef HOME_PANE_H
#define HOME_PANE_H

#include "PaneInterface.h"

class HomePane : public PaneInterface {
public:
    void render() override;
    void handle_input(char c) override;
};

#endif
