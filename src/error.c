#include "u2f-emu.h"


const char *u2f_emu_strerror(u2f_emu_rc rc)
{
    switch (rc)
    {
        case U2F_EMU_OK:
            return "Successful operatuin";
        case U2F_EMU_MEMORY_ERROR:
            return "Memory error";
        case U2F_EMU_TRANSPORT_ERROR:
            return "Transport error";
        case U2F_EMU_PERMISSION_ERROR:
            return "Not allowed";
        case U2F_EMU_SUPPORTED_ERROR:
            return "Not supported";
        default:
            break;
    }
    return "Unknow error";
}
