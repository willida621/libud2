#include "ud2hook.hpp"
ud2hook::scoped_patch::scoped_patch(LPVOID addr, const std::vector<BYTE>& bytes)
    : m_addr(addr), m_original(bytes.size()) {
    // store original bytes and apply new ones
    DWORD oldProtect;
    VirtualProtect(m_addr, bytes.size(), PAGE_EXECUTE_READWRITE, &oldProtect);
    memcpy(m_original.data(), m_addr, bytes.size());
    memcpy(m_addr, bytes.data(), bytes.size());
    VirtualProtect(m_addr, bytes.size(), oldProtect, &oldProtect);
}
ud2hook::scoped_patch::~scoped_patch() {
    // restore original bytes when going out of scope
    DWORD oldProtect;
    VirtualProtect(m_addr, m_original.size(), PAGE_EXECUTE_READWRITE, &oldProtect);
    static const BYTE ud2[] = { 0x0F, 0x0B };
    memcpy(m_addr, ud2, sizeof(ud2));
    VirtualProtect(m_addr, m_original.size(), oldProtect, &oldProtect);
}
ud2hook::hook_status ud2hook::install_hook(LPVOID target_func, LPVOID detour_func, hook_callback pre_callback) {
    if (!target_func || !detour_func)
        return hook_status::invalid_function;
    if (s_hooks.count(target_func))
        return hook_status::already_hooked;
    // set up vectored exception handler if this is the first hook
    if (s_hooks.empty() && !s_vectored_handler) {
        s_vectored_handler = AddVectoredExceptionHandler(1, vectored_exception_hander);
        if (!s_vectored_handler)
            return hook_status::handler_installation_failed;
    }
    // prepare hook data structure
    hook_data hook;
    hook.detour_func = detour_func;
    hook.pre_callback = pre_callback;
    const size_t patch_size = 2;
    hook.original_bytes.resize(patch_size);
    memcpy(hook.original_bytes.data(), target_func, patch_size);
    hook.original_func = target_func;
    // apply the ud2 instruction patch
    auto status = apply_ud2_patch(target_func);
    if (status != hook_status::success)
        return status;
    // store hook information
    s_hooks[target_func] = std::move(hook);
    return hook_status::success;
}
ud2hook::hook_status ud2hook::install_hook_at_address(DWORD_PTR target_address, LPVOID detour_func, hook_callback pre_callback)
{
    if (!target_address || !detour_func)
        return hook_status::invalid_address;
    // check if address is valid for hooking
    if (!is_valid_address(target_address))
        return hook_status::invalid_address;
    LPVOID target_func = reinterpret_cast<LPVOID>(target_address);
    if (s_hooks.count(target_func))
        return hook_status::already_hooked;
    // set up vectored exception handler if this is the first hook
    if (s_hooks.empty() && !s_vectored_handler) {
        s_vectored_handler = AddVectoredExceptionHandler(1, vectored_exception_hander);
        if (!s_vectored_handler)
            return hook_status::handler_installation_failed;
    }
    // prepare hook data structure
    hook_data hook;
    hook.detour_func = detour_func;
    hook.pre_callback = pre_callback;
    const size_t patch_size = 2;
    hook.original_bytes.resize(patch_size);
    // try to read original bytes with protection
   try {
    memcpy(hook.original_bytes.data(), target_func, patch_size);
    }
    catch (...) {
        return hook_status::invalid_address;
    }
    hook.original_func = target_func;
    // apply the ud2 instruction patch
    auto status = apply_ud2_patch(target_func);
    if (status != hook_status::success)
        return status;
    // store hook information
    s_hooks[target_func] = std::move(hook);
    return hook_status::success;
}
ud2hook::hook_status ud2hook::remove_hook(LPVOID target_func)
{
    if (!target_func)
        return hook_status::invalid_function;
    // find and remove hook from storage
    auto it = s_hooks.find(target_func);
    if (it == s_hooks.end())
        return hook_status::not_hooked;
    // restore original bytes
    auto status = restore_original_bytes(target_func);
    if (status != hook_status::success)
        return status;
    s_hooks.erase(it);
    // clean up vectored exception handler if no hooks remain
    if (s_hooks.empty() && s_vectored_handler) {
        if (!RemoveVectoredExceptionHandler(s_vectored_handler))
            return hook_status::handler_removal_failed;
        s_vectored_handler = nullptr;
    }
    return hook_status::success;
}
ud2hook::hook_status ud2hook::remove_hook_at_address(DWORD_PTR target_address)
{
    if (!target_address)
        return hook_status::invalid_address;
    LPVOID target_func = reinterpret_cast<LPVOID>(target_address);
    return remove_hook(target_func);
}
ud2hook::hook_data &ud2hook::get_hook_data(LPVOID target_func)
{
    auto it = s_hooks.find(target_func);
    if (it == s_hooks.end())
        throw std::runtime_error("hook not found");
    return it->second;
}
bool ud2hook::is_valid_address(DWORD_PTR address)
{
    if (!address)
        return false;
    MEMORY_BASIC_INFORMATION mbi;
    if (VirtualQuery(reinterpret_cast<LPCVOID>(address), &mbi, sizeof(mbi)) == 0)
        return false;
    // check if memory is commited and has executable permissions
    if (mbi.State != MEM_COMMIT)
        return false;
    if (!(mbi.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)))
        return false;
    return true;
}
LONG __stdcall ud2hook::vectored_exception_hander(PEXCEPTION_POINTERS p_exception_info) {
    // check for illegal instruction exception
    if (p_exception_info->ExceptionRecord->ExceptionCode == STATUS_ILLEGAL_INSTRUCTION) {
        // find hook associated with this address
        auto it = s_hooks.find(p_exception_info->ExceptionRecord->ExceptionAddress);
        if (it != s_hooks.end()) {
            auto& hook = it->second;
            PCONTEXT ctx = p_exception_info->ContextRecord;
            // execute pre-callback if registered
            if (hook.pre_callback) {
                #if defined(_M_IX86)
                    hook.pre_callback(reinterpret_cast<void**>(&ctx->Eip));
                #elif defined(_M_X64)
                    hook.pre_callback(reinterpret_cast<void**>(&ctx->Rip));
                #endif
            }
            // redirect execution to detour function
            #if defined(_M_IX86)
                ctx->Eip = reinterpret_cast<DWORD>(hook.detour_func);
            #elif defined(_M_X64)
                ctx->Rip = reinterpret_cast<DWORD64>(hook.detour_func);
            #endif
            
            return EXCEPTION_CONTINUE_EXECUTION;
        }
    }
    return EXCEPTION_CONTINUE_SEARCH;
}
ud2hook::hook_status ud2hook::apply_ud2_patch(LPVOID target_func)
{
    // change memory protection and write ud2 instruction
    DWORD oldProtect;
    if (!VirtualProtect(target_func, 2, PAGE_EXECUTE_READWRITE, &oldProtect)) {
        return hook_status::memory_protection_failed;
    }
    static const BYTE ud2[] = { 0x0F, 0x0B };
    memcpy(target_func, ud2, sizeof(ud2));
    VirtualProtect(target_func, 2, oldProtect, &oldProtect);
    return hook_status::success;
}
ud2hook::hook_status ud2hook::restore_original_bytes(LPVOID target_func) {
    // get original bytes from hook data and restore them
    auto& hook = get_hook_data(target_func);
    DWORD oldProtect;
    if (!VirtualProtect(target_func, hook.original_bytes.size(), PAGE_EXECUTE_READWRITE, &oldProtect))
        return hook_status::memory_protection_failed;
    memcpy(target_func, hook.original_bytes.data(), hook.original_bytes.size());
    VirtualProtect(target_func, hook.original_bytes.size(), oldProtect, &oldProtect);
    return hook_status::success;
}
