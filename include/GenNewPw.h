#ifndef GEN_PW_H
#define GEN_PW_H

#include "PaneInterface.h"

class GeneratePwPane : public PaneInterface {
public:
    void render() override;
    void handle_input(char c) override;
};

#endif
