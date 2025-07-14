#ifndef ADD_DB_H
#define ADD_DB_H

#include "PaneInterface.h"

class AddDbPane : public PaneInterface {
public:
    void render() override;
    void handle_input(char c) override;
};

#endif
