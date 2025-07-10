#pragma once
#include <Windows.h>
#include <vector>
#include <functional>
#include <memory>
#include <stdexcept>
#include <unordered_map>
#include <type_traits>
/**
 * provides UD2-based function hooking mechanism
 * @note uses int 3 (UD2) instruction to trigger hook handling
 * @warning not thread-safe during hook installation/removal
*/
class ud2hook {
public:
    /**
     * represents hook operation status
     * @note all values are self-descriptive
    */
    enum class hook_status {
        success,                     // operation completed successfully
        already_hooked,              // function is already hooked
        not_hooked,                  // function is not hooked
        memory_protection_failed,    // failed to change memory protection
        handler_installation_failed, // failed to install exception handler
        handler_removal_failed,      // failed to remove exception handler
        invalid_function,            // invalid function pointer
        invalid_address,             // invalid memory address  
        unknown_error                // unspecified error occurred
    };
    /**
     * callback type executed before detour function
     * @param rip_ptr pointer to instruction pointer
     * @note can modify execution flow by changing rip
    */
    using hook_callback = std::function<void(void**)>;
    /**
     * installs hook at function pointer
     * @param target_func function to hook
     * @param detour_func replacement function
     * @param pre_callback optional pre-detour callback
     * @return hook_status indicating operation result
     * @note automatically handles exception handler registration
    */
    static hook_status install_hook(LPVOID target_func, LPVOID detour_func, hook_callback pre_callback = nullptr);
    /**
     * installs hook at memory address
     * @param target_address memory location to hook
     * @param detour_func replacement function
     * @param pre_callback optional pre-detour callback
     * @return hook_status indicating operation result
     * @note performs basic address validation
    */
    static hook_status install_hook_at_address(DWORD_PTR target_address, LPVOID detour_func, hook_callback pre_callback = nullptr);
    /**
     * type-safe version of address hooking
     * @tparam DetourFunc function pointer type
     * @param target_address memory location to hook
     * @param detour_func replacement function
     * @param pre_callback optional pre-detour callback
     * @return hook_status indicating operation result
     * @note automatically handles type conversion
    */
    template<typename DetourFunc>
    static hook_status install_hook_at_address(DWORD_PTR target_address, DetourFunc detour_func, hook_callback pre_callback = nullptr) {
        return install_hook_at_address(target_address, reinterpret_cast<LPVOID>(detour_func), pre_callback);
    }
    /**
     * removes installed hook
     * @param target_func hooked function
     * @return hook_status indicating operation result
     * @note automatically cleans up if last hook
    */
    static hook_status remove_hook(LPVOID target_func);
    /**
     * removes hook by address
     * @param target_address hooked memory location
     * @return hook_status indicating operation result
     * @note convenience wrapper for remove_hook
    */
    static hook_status remove_hook_at_address(DWORD_PTR target_address);
    /**
     * calls original function (direct version)
     * @tparam func_type function signature type
     * @tparam Args argument types
     * @param args arguments to forward
     * @return result of original function
     * @note requires original pointer as first argument
    */
    template<typename func_type, typename... Args>
    static auto call_original(Args&&... args) -> decltype(std::declval<func_type>()(std::forward<Args>(args)...)) {
        // this version requires the original pointer as first argument
        // usage: call_original<MessageBoxA_t>(original_ptr, hWnd, lpText, lpCaption, uType)
        static_assert(std::is_pointer<func_type>::value, "func_type must be a function pointer");
        return reinterpret_cast<func_type>(std::forward<Args>(args)...);
    }
    /**
     * calls original function by target address
     * @tparam func_type function signature type
     * @tparam Args argument types
     * @param target_func hooked function
     * @param args arguments to forward
     * @return result of original function
     * @throws std::runtime_error if hook not found
     * @note temporarily restores original code
    */
    template<typename func_type, typename... Args>
    static auto call_original_by_addr(LPVOID target_func, Args&&... args)
        -> decltype(std::declval<func_type>()(std::forward<Args>(args)...)) {
        auto& hook = get_hook_data(target_func);
        if (!hook.original_bytes.empty()) {
            scoped_patch scoped(target_func, hook.original_bytes);
            return reinterpret_cast<func_type>(hook.original_func)(std::forward<Args>(args)...);
        }
        throw std::runtime_error("original function not available");
    }
     /**
     * calls original function by memory address
     * @tparam func_type function signature type
     * @tparam Args argument types
     * @param target_address hooked memory location
     * @param args arguments to forward
     * @return result of original function
     * @note convenience wrapper for call_original_by_addr
    */
    template<typename func_type, typename... Args>
    static auto call_original_by_address(DWORD_PTR target_address, Args&&... args)
        -> decltype(std::declval<func_type>()(std::forward<Args>(args)...)) {
        LPVOID target_func = reinterpret_cast<LPVOID>(target_address);
        return call_original_by_addr<func_type>(target_func, std::forward<Args>(args)...);
    }
    /**
     * automatically calls original function
     * @tparam func_type function signature type
     * @tparam Args argument types
     * @param original_func_ptr original function pointer
     * @param args arguments to forward
     * @return result of original function
     * @note searches hook registry automatically
    */
    template<typename func_type, typename... Args>
    static auto call_original_auto(func_type original_func_ptr, Args&&... args)
        -> decltype(original_func_ptr(std::forward<Args>(args)...)) {
        // find the target function in our hook registry
        LPVOID target_func = reinterpret_cast<LPVOID>(original_func_ptr);
        for (auto& [addr, hook_data] : s_hooks) {
            if (hook_data.original_func == target_func) {
                scoped_patch patch(addr, hook_data.original_bytes);
                return original_func_ptr(std::forward<Args>(args)...);
            }
        }
        // if not found in hooks, call directly (might be unhooked)
        return original_func_ptr(std::forward<Args>(args)...);
    }
    /**
     * checks if address is valid for hooking
     * @param address memory location to check
     * @return true if address is executable and valid
     * @note uses VirtualQuery for validation
    */
    static bool is_valid_address(DWORD_PTR address);
private:
    /**
     * contains hook metadata
     * @note internal use only
    */
    struct hook_data {
        std::vector<BYTE> original_bytes; // original bytes replaced by the hook
        LPVOID original_func = nullptr; // pointer to the original function
        LPVOID detour_func = nullptr; // pointer to the detour function that will be called instead
        hook_callback pre_callback; // original callback to execute before calling the detour
    };
    /**
     * RAII wrapper for temporary memory patches
     * @note automatically restores original bytes
    */
    struct scoped_patch {
        /**
         * applies memory patch
         * @param addr address to patch
         * @param bytes new bytes to write
        */
        scoped_patch(LPVOID addr, const std::vector<BYTE>& bytes);
        /**
         * restores original bytes
        */
        ~scoped_patch();
    private:
        LPVOID m_addr; // address where the patch is applied
        std::vector<BYTE> m_original; // original bytes that were replaced by the patch
    };
    // retrieves hook data for given target function
    static hook_data& get_hook_data(LPVOID target_func);
    // handles exceptions caused by ud2 instructions
    static LONG WINAPI vectored_exception_hander(PEXCEPTION_POINTERS p_exception_info);
    // applies ud2 instruction patch to target function
    static hook_status apply_ud2_patch(LPVOID target_func);
    // restores original bytes of hooked function
    static hook_status restore_original_bytes(LPVOID target_func);
    // storage for all active hooks
    static inline std::unordered_map<LPVOID, hook_data> s_hooks;
    // handle for our vectored exception handler
    static inline PVOID s_vectored_handler = nullptr;
public:
    /**
     * RAII wrapper for automatic hook management
     * @note removes hook automatically on destruction
    */
    class auto_hook {
    public:
    /**
    * constructs a hook by function pointer
    * @tparam FuncPtr type of the target function pointer
    * @tparam DetourFunc type of the detour function
    * @param target_func pointer to the function to be hooked
    * @param detour_func pointer to the detour function
    * @param pre_callback optional callback executed before detour
    * @note automatically installs the hook on construction
    */
    template<typename FuncPtr, typename DetourFunc>
    auto_hook(FuncPtr target_func, DetourFunc detour_func, hook_callback  pre_callback = nullptr)
        : m_target_addr(reinterpret_cast<DWORD_PTR>(target_func))
        , m_is_valid(false)
        , m_is_address_based(false) {
        auto status = ud2hook::install_hook(
            reinterpret_cast<LPVOID>(target_func),
            reinterpret_cast<LPVOID>(detour_func),
            pre_callback
        );
        m_is_valid = (status == hook_status::success);
    }
    /**
       * constructs a hook by memory address
    * @tparam DetourFunc type of the detour function
    * @param target_address memory address to hook
    * @param detour_func pointer to the detour function
    * @param pre_callback optional callback executed before detour
    * @note automatically installs the hook on construction
    */
    template<typename DetourFunc>
    auto_hook(DWORD_PTR target_address, DetourFunc detour_func, hook_callback pre_callback = nullptr)
        : m_target_addr(target_address)
        , m_is_valid(false)
        , m_is_address_based(true) {
        auto status = ud2hook::install_hook_at_address(
            target_address,
            reinterpret_cast<LPVOID>(detour_func),
            pre_callback
        );
        m_is_valid = (status == hook_status::success);
    }
    /**
     * constructs a hook with combined callbacks
     * @tparam DetourFunc type of the detour function
     * @tparam ContextCallback type of additional context callback
     * @param target_address memory address to hook
     * @param detour_func pointer to the detour function
     * @param pre_callback primary callback executed before detour
     * @param context_callback additional context callback
     * @note merges both callbacks into single execution chain
     */
    template<typename DetourFunc, typename ContextCallback>
    auto_hook(DWORD_PTR target_address, DetourFunc detour_func, hook_callback pre_callback, ContextCallback context_callback)
        : m_target_addr(target_address)
        , m_is_valid(false)
        , m_is_address_based(true) {
        // create a combined callback that calls both pre_callback and context_callback
        hook_callback combined_callback = nullptr;
        if (pre_callback || context_callback) {
            combined_callback = [pre_callback, context_callback](void** ctx) {
                if (pre_callback)
                    pre_callback(ctx);
                if (context_callback)
                    context_callback(ctx);
            };
        }
        auto status = ud2hook::install_hook_at_address(
            target_address,
            reinterpret_cast<LPVOID>(detour_func),
            combined_callback
        );
        m_is_valid = (status == hook_status::success);
    }
    /**
     * destructor automatically removes the hook
     * @note safe to call even if hook installation failed
     */
    ~auto_hook() {
        if (m_is_valid) {
            if (m_is_address_based)
                ud2hook::remove_hook_at_address(m_target_addr);
            else
                ud2hook::remove_hook(reinterpret_cast<LPVOID>(m_target_addr));
        }
    }
    // non-copyable to prevent duplicate hook management
    auto_hook(const auto_hook&) = delete;
    auto_hook& operator=(const auto_hook&) = delete;
    /**
     * move constructor transfers hook ownership
     * @param other hook to move from
     * @note invalidates the source object
     */
    auto_hook(auto_hook&& other) noexcept
        : m_target_addr(other.m_target_addr)
        , m_is_valid(other.m_is_valid)
        , m_is_address_based(other.m_is_address_based) {
        other.m_is_valid = false; // prevent other from removing the hook
    }
    /**
     * move assignment transfers hook ownership
     * @param other hook to move from
     * @note properly handles self-assignment
     */
    auto_hook& operator=(auto_hook&& other) noexcept {
        if (this != &other) {
            // Remove current hook if valid
            if (m_is_valid) {
                if (m_is_address_based) {
                    ud2hook::remove_hook_at_address(m_target_addr);
                } else {
                    ud2hook::remove_hook(reinterpret_cast<LPVOID>(m_target_addr));
                }
            }
            // Move from other
            m_target_addr = other.m_target_addr;
            m_is_valid = other.m_is_valid;
            m_is_address_based = other.m_is_address_based;
            other.m_is_valid = false; // Prevent other from removing the hook
        }
        return *this;
    }
    /**
     * calls the original hooked function
     * @tparam func_type function signature type
     * @tparam Args argument types
     * @param args arguments to forward
     * @return result of the original function
     * @throws std::runtime_error if hook is invalid
     * @note temporarily restores original code during call
     */
    template<typename func_type, typename... Args>
    auto call_original(Args&&... args) -> decltype(std::declval<func_type>()(std::forward<Args>(args)...)) {
        if (!m_is_valid) {
            throw std::runtime_error("hook is not valid");
        }
        return ud2hook::call_original_by_address<func_type>(m_target_addr, std::forward<Args>(args)...);
    }
    private:
        DWORD_PTR m_target_addr;    // stored target address
        bool m_is_valid;            // hook installation status
        bool m_is_address_based;    // address-based hook flag
    };
};
