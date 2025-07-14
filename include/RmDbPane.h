#ifndef RM_DB_H 
#define RM_DB_H

#include "PaneInterface.h"

class RemoveDBPane : public PaneInterface {
public:
    void render() override;
    void handle_input(char c) override;
};

#endif
