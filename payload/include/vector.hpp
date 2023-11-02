// itlib-pod-vector v1.07
//
// A vector of PODs. Similar to std::vector, but doesn't call constructors or
// destructors and instead uses memcpy and memmove to manage the data
//
// SPDX-License-Identifier: MIT
// MIT License:
// Copyright(c) 2020-2023 Borislav Stanimirov
//
// Permission is hereby granted, free of charge, to any person obtaining
// a copy of this software and associated documentation files(the
// "Software"), to deal in the Software without restriction, including
// without limitation the rights to use, copy, modify, merge, publish,
// distribute, sublicense, and / or sell copies of the Software, and to
// permit persons to whom the Software is furnished to do so, subject to
// the following conditions :
//
// The above copyright notice and this permission notice shall be
// included in all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
// EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
// MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
// NONINFRINGEMENT.IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
// LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
// OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
// WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
//
//
//                  VERSION HISTORY
//
//  1.07 (2023-01-18) Use std::copy and std::fill. This does help compilers
//                    generate better code (expecially MSVC)
//  1.06 (2022-08-26) Inherit from allocator to make use of EBO
//  1.05 (2022-06-09) Support for alignment of T.
//                    Requires aloc_align from allocator implementations!
//                    Support for expand allocator func
//                    Requires has_expand from allocator implementations!
//                    Other minor internal cleanups
//  1.04 (2021-08-05) Bugfix! Fixed return value of erase
//  1.03 (2021-06-08) Prevent memcmp calls with nullptr
//  1.02 (2021-06-08) Noexcept move ctor and move assignment operator
//  1.01 (2020-10-28) Switched static assert from is_pod to is_trivial
//  1.00 (2020-10-18) Initial release
//
//
//                  DOCUMENTATION
//
// Simply include this file wherever you need.
// It defines the class itlib::pod_vector, which similar to std::vector:
// * It keeps the data in a contiguous memory block
// * Has the same public methods and operators and features like random-access
// But:
// * Operates only ot PODs
// * Doesn't call constructors, destructors, move and assign operators
// * Instead uses memcpy and memmove to manage the data
// Thus, it achieves a much better performance, especially in Debug mode.
//
// pod_vector also allows "recast" where you can convert pod_vector<T> to
// pod_vector<U>. This is very useful when operating with signed/unsigned char
// for example.
//
// except for the methods which are the same as std::vector, itlib::pod_vector
// also provides the following:
// * size_t byte_size() const; - size of data in bytes
// * recast_copy_from(other_vec) - copies from other vec. Note that this will
//   lose data if the byte size of other_vec's data is not divisible by
//   sizeof(T)
// * recast_take_from(other_vec) - moves from other vec. Note that this will
//   lose data if the byte size of other_vec's data is not divisible by
//   sizeof(T)
//
// pod_vector uses pod_allocator, which needs to have methods to allocate,
// deallocate, and reallocate. The default version uses malloc, free, and
// realloc. If you make your own allocator you must conform to the definitons
// of these functions.
// The allocator must provide the following interface:
// * using size_type = ...; - size type for allocator and vector
// * void* malloc(size_type size); - allocate memory
// * void free(void* mem); - free memory which was allocated here
// * size_type max_size(); - max available memory
// * bool zero_fill_new(); - whether pod_vector should to zerofill new elements
// * size_type alloc_align() - guaranteed min alignment of malloc and realloc
//                             MUST BE static constexpr
// * bool has_expand() - whether to use the expand or realloc interface
//                       MUST BE static constexpr
// * void* realloc(void* old, size_type new_size) - allocate/reallocate memory
//                                                  ONLY IF has_expand is false
// * size_type realloc_wasteful_copy_size() - when to use reallocate on grows
//                                            ONLY IF has_expand is false
// * bool expand(void* ptr, size_type new_size) - try to expand buf
//                                                ONLY IF has_expand is true
//
//                  TESTS
//
// You can find unit tests in the official repo:
// https://github.com/iboB/itlib/blob/master/test/
//
#pragma once

#include <type_traits>
#include <cstddef>
#include <cstdlib>
#include <iterator>
#include <cstring>
#include <cstdint>
#include <algorithm>

namespace itlib
{

namespace impl
{
class pod_allocator
{
  public:
    using size_type = size_t;
    static void* malloc(size_type size)
    {
        return std::malloc(size);
    }
    static void free(void* mem)
    {
        std::free(mem);
    }

    static constexpr size_type max_size()
    {
        return ~size_type(0);
    }
    static constexpr bool zero_fill_new()
    {
        return true;
    }
    static constexpr size_type alloc_align()
    {
        return alignof(max_align_t);
    }
    static constexpr bool has_expand()
    {
        return false;
    }
    static bool expand(void*, size_t)
    {
        return false;
    }
    static void* realloc(void* old, size_type new_size)
    {
        return std::realloc(old, new_size);
    }
    static constexpr size_type realloc_wasteful_copy_size()
    {
        return 4096;
    }
};
} // namespace impl

template <typename T, class Alloc = impl::pod_allocator> class pod_vector : private Alloc
{
    static_assert(std::is_trivial<T>::value, "itlib::pod_vector with non-trivial type");
    static_assert(alignof(T) <= 128, "alignment of T is too big"); // max supported alignment

    template <typename U, typename A> friend class pod_vector; // so we can move between types

  public:
    using allocator_type         = Alloc;
    using value_type             = T;
    using size_type              = typename Alloc::size_type;
    using reference              = T&;
    using const_reference        = const T&;
    using pointer                = T*;
    using const_pointer          = const T*;
    using iterator               = pointer;
    using const_iterator         = const_pointer;
    using reverse_iterator       = std::reverse_iterator<iterator>;
    using const_reverse_iterator = std::reverse_iterator<const_iterator>;

    pod_vector() : pod_vector(Alloc())
    {
    }

    explicit pod_vector(const Alloc& alloc) : Alloc(alloc), m_capacity(0)
    {
        m_begin = m_end = nullptr;
    }

    explicit pod_vector(size_t count, const Alloc& alloc = Alloc()) : pod_vector(alloc)
    {
        resize(count);
    }

    pod_vector(size_t count, const T& value, const Alloc& alloc = Alloc()) : pod_vector(alloc)
    {
        assign_fill(count, value);
    }

    template <typename InputIterator, typename = decltype(*std::declval<InputIterator>())>
    pod_vector(InputIterator first, InputIterator last, const Alloc& alloc = Alloc()) : pod_vector(alloc)
    {
        assign_copy(first, last);
    }

    pod_vector(std::initializer_list<T> l, const Alloc& alloc = Alloc()) : pod_vector(alloc)
    {
        assign_copy(l.begin(), l.end());
    }

    pod_vector(const pod_vector& other) : pod_vector(other, other.get_allocator())
    {
    }

    pod_vector(const pod_vector& other, const Alloc& alloc) : pod_vector(alloc)
    {
        assign_copy(other.begin(), other.end());
    }

    pod_vector(pod_vector&& other) noexcept
        : Alloc(std::move(other.get_alloc()))
        , m_begin(other.m_begin)
        , m_end(other.m_end)
        , m_capacity(other.m_capacity)
    {
        other.m_begin = other.m_end = nullptr;
        other.m_capacity            = 0;
    }

    ~pod_vector()
    {
        a_free_begin();
    }

    pod_vector& operator=(const pod_vector& other)
    {
        if (this == &other)
            return *this; // prevent self usurp
        clear();
        assign_copy(other.begin(), other.end());
        return *this;
    }

    pod_vector& operator=(pod_vector&& other) noexcept
    {
        if (this == &other)
            return *this; // prevent self usurp

        a_free_begin();

        get_alloc() = std::move(other.get_alloc());
        m_capacity  = other.m_capacity;
        m_begin     = other.m_begin;
        m_end       = other.m_end;

        other.m_begin = other.m_end = nullptr;
        other.m_capacity            = 0;

        return *this;
    }

    template <typename U, typename UAlloc> void recast_copy_from(const pod_vector<U, UAlloc>& other)
    {
        clear();
        auto new_size = other.byte_size() / sizeof(T);
        auto cast     = reinterpret_cast<const T*>(other.data());
        assign_copy(cast, cast + new_size);
    }

    template <typename U, typename UAlloc> void recast_take_from(pod_vector<U, UAlloc>&& other)
    {
        static_assert(
            allocator_aligned() == pod_vector<U, UAlloc>::allocator_aligned(),
            "taking buffers can only happen with the same relative allocation alignment"
        );

        a_free_begin();

        auto new_size = other.byte_size() / sizeof(T);
        auto cast     = reinterpret_cast<T*>(other.data());
        m_begin       = cast;
        m_end         = m_begin + new_size;

        m_capacity = (sizeof(U) * other.capacity()) / sizeof(T);

        // This needs to be a valid op for recasts to work
        // it this line does not compile, you need to ensure allocator compatibility for it
        get_alloc() = std::move(other.get_alloc());

        other.m_begin = other.m_end = nullptr;
        other.m_capacity            = 0;
    }

    void assign(size_type count, const T& value)
    {
        assign_fill(count, value);
    }

    template <typename InputIterator, typename = decltype(*std::declval<InputIterator>())>
    void assign(InputIterator first, InputIterator last)
    {
        assign_copy(first, last);
    }

    void assign(std::initializer_list<T> ilist)
    {
        assign_copy(ilist.begin(), ilist.end());
    }

    const allocator_type& get_allocator() const noexcept
    {
        return get_alloc();
    }

    const_reference at(size_type i) const
    {
        return *(m_begin + i);
    }

    reference at(size_type i)
    {
        return *(m_begin + i);
    }

    const_reference operator[](size_type i) const
    {
        return at(i);
    }

    reference operator[](size_type i)
    {
        return at(i);
    }

    const_reference front() const
    {
        return at(0);
    }

    reference front()
    {
        return at(0);
    }

    const_reference back() const
    {
        return *(m_end - 1);
    }

    reference back()
    {
        return *(m_end - 1);
    }

    const_pointer data() const noexcept
    {
        return m_begin;
    }

    pointer data() noexcept
    {
        return m_begin;
    }

    // iterators
    iterator begin() noexcept
    {
        return m_begin;
    }

    const_iterator begin() const noexcept
    {
        return m_begin;
    }

    const_iterator cbegin() const noexcept
    {
        return m_begin;
    }

    iterator end() noexcept
    {
        return m_end;
    }

    const_iterator end() const noexcept
    {
        return m_end;
    }

    const_iterator cend() const noexcept
    {
        return m_end;
    }

    reverse_iterator rbegin() noexcept
    {
        return reverse_iterator(end());
    }

    const_reverse_iterator rbegin() const noexcept
    {
        return const_reverse_iterator(end());
    }

    const_reverse_iterator crbegin() const noexcept
    {
        return const_reverse_iterator(end());
    }

    reverse_iterator rend() noexcept
    {
        return reverse_iterator(begin());
    }

    const_reverse_iterator rend() const noexcept
    {
        return const_reverse_iterator(begin());
    }

    const_reverse_iterator crend() const noexcept
    {
        return const_reverse_iterator(begin());
    }

    // capacity
    bool empty() const noexcept
    {
        return m_begin == m_end;
    }

    size_type size() const noexcept
    {
        return m_end - m_begin;
    }

    size_t max_size() const noexcept
    {
        return Alloc::max_size();
    }

    size_t byte_size() const noexcept
    {
        return e2b(size());
    }

    void reserve(size_t desired_capacity)
    {
        if (desired_capacity <= m_capacity)
            return;

        auto new_cap = get_new_capacity(desired_capacity);
        auto s       = size();

        auto malloc_copy = [&]()
        {
            auto new_buf = pointer(a_malloc(new_cap));
            if (s)
                memcpy(new_buf, m_begin, byte_size());
            a_free_begin();
            m_begin    = new_buf;
            m_capacity = new_cap;
        };

        if (Alloc::has_expand())
        {
            if (!m_begin)
            {
                m_begin    = pointer(a_malloc(new_cap));
                m_capacity = new_cap;
            }
            else if (!a_expand_begin(new_cap))
            {
                malloc_copy();
            }
        }
        else
        {
            if (e2b(m_capacity - s) > Alloc::realloc_wasteful_copy_size())
            {
                // we decided that it would be more wasteful to use realloc and
                // copy more than needed than it would be to malloc and manually copy
                malloc_copy();
            }
            else
            {
                a_realloc_begin(new_cap);
            }
        }

        m_end = m_begin + s;
    }

    size_t capacity() const noexcept
    {
        return m_capacity;
    }

    void shrink_to_fit()
    {
        const auto s = size();

        if (s == m_capacity)
            return;

        if (s == 0)
        {
            a_free_begin();
            m_capacity = 0;
            m_begin = m_end = nullptr;
            return;
        }

        if (Alloc::has_expand())
        {
            if (!a_expand_begin(s))
            {
                // uh-oh expand-shrink failed?
                auto new_buf = a_malloc(s);
                std::memcpy(new_buf, m_begin, e2b(s));
                a_free_begin();
                m_begin    = pointer(new_buf);
                m_capacity = s;
            }
        }
        else
        {
            a_realloc_begin(s);
        }

        m_end = m_begin + s;
    }

    // modifiers
    void clear() noexcept
    {
        m_end = m_begin;
    }

    iterator insert(const_iterator position, const value_type& val)
    {
        auto pos = grow_at(position, 1);
        *pos     = val;
        return pos;
    }

    iterator insert(const_iterator position, size_type count, const value_type& val)
    {
        auto pos = grow_at(position, count);
        fill(pos, count, val);
        return pos;
    }

    template <typename InputIterator, typename = decltype(*std::declval<InputIterator>())>
    iterator insert(const_iterator position, InputIterator first, InputIterator last)
    {
        auto pos = grow_at(position, last - first);
        copy_not_aliased(pos, first, last);
        return pos;
    }

    iterator insert(const_iterator position, std::initializer_list<T> ilist)
    {
        auto pos = grow_at(position, ilist.size());
        copy_not_aliased(pos, ilist.begin(), ilist.end());
        return pos;
    }

    // for compatibility
    iterator emplace(const_iterator position, const_reference& val)
    {
        return insert(position, val);
    }

    iterator erase(const_iterator position)
    {
        return shrink_at(position, 1);
    }

    iterator erase(const_iterator first, const_iterator last)
    {
        return shrink_at(first, last - first);
    }

    // for compatibility
    reference emplace_back()
    {
        reserve(size() + 1);
        ++m_end;
        return back();
    }

    reference push_back(const_reference val)
    {
        return emplace_back() = val;
    }

    // for compatibility
    reference emplace_back(const_reference val)
    {
        return push_back(val);
    }

    void pop_back()
    {
        shrink_at(m_end - 1, 1);
    }

    void resize(size_type n, const value_type& val)
    {
        reserve(n);
        fill(m_end, n, val);
        m_end = m_begin + n;
    }

    void resize(size_type n)
    {
        reserve(n);
        if (n > size() && Alloc::zero_fill_new())
        {
            std::memset(m_end, 0, e2b(n - size()));
        }
        m_end = m_begin + n;
    }

    void swap(pod_vector& other)
    {
        auto tmp = std::move(other);
        other    = std::move(*this);
        *this    = std::move(tmp);
    }

  private:
    // fill count elements from p with value
    static void fill(T* p, size_type count, const T& value)
    {
        std::fill(p, p + count, value);
    }

    template <typename InputIterator>
    static void copy_not_aliased(T* p, InputIterator begin, InputIterator end)
    {
        std::copy(begin, end, p);
    }

    // still for extra help, we can provide this (alsto it will be faster in debug)
    static void copy_not_aliased(T* p, const T* begin, const T* end)
    {
        auto s = e2b(size_t(end - begin));
        if (s == 0)
            return;
        std::memcpy(p, begin, s);
    }

    // calculate a new capacity so that it's at least desired_capacity
    size_type get_new_capacity(size_type desired_capacity) const
    {
        if (m_capacity == 0)
        {
            return desired_capacity;
        }
        else
        {
            auto new_cap = m_capacity;

            while (new_cap < desired_capacity)
            {
                // grow by roughly 1.5
                new_cap *= 3;
                ++new_cap;
                new_cap /= 2;
            }

            return new_cap;
        }
    }

    // increase the size by splicing the elements in such a way that
    // a hole of uninitialized elements is left at position, with size num
    // returns the (potentially new) address of the hole
    T* grow_at(const T* cp, size_type num)
    {
        const auto s      = size();
        auto       offset = cp - m_begin;

        if (cp == m_end)
        {
            resize(s + num);
        }
        else
        {
            auto make_gap = [&]()
            {
                std::memmove(m_begin + offset + num, m_begin + offset, e2b(s - offset));
            };

            if (s + num > m_capacity)
            {
                auto new_cap = get_new_capacity(s + num);

                auto malloc_copy = [&]()
                {
                    // we decided that it would be more wasteful to use realloc and
                    // copy more than needed than it would be to malloc and manually copy
                    auto new_buf = pointer(a_malloc(new_cap));
                    if (offset)
                        memcpy(new_buf, m_begin, e2b(offset));
                    memcpy(new_buf + offset + num, m_begin + offset, e2b(s - offset));
                    a_free_begin();
                    m_begin    = new_buf;
                    m_capacity = new_cap;
                };

                if (Alloc::has_expand())
                {
                    if (a_expand_begin(new_cap))
                    {
                        make_gap();
                    }
                    else
                    {
                        malloc_copy();
                    }
                }
                else
                {
                    if (e2b(m_capacity - offset) > Alloc::realloc_wasteful_copy_size())
                    {
                        malloc_copy();
                    }
                    else
                    {
                        a_realloc_begin(new_cap);
                        make_gap();
                    }
                }
            }
            else
            {
                make_gap();
            }
        }

        m_end = m_begin + s + num;
        return m_begin + offset;
    }

    // remove elements from cp to cp+num, shifting the rest
    // returns one after the removed
    T* shrink_at(const T* cp, size_type num)
    {
        const auto s = size();
        if (s == num)
        {
            clear();
            return m_end;
        }

        auto position = const_cast<T*>(cp);

        std::memmove(position, position + num, e2b(size_t(m_end - position - num)));

        m_end -= num;

        return position;
    }

    // grows buffer only on empty vectors
    void safe_grow(size_t capacity)
    {
        if (capacity <= m_capacity)
            return;

        a_free_begin();

        m_capacity = get_new_capacity(capacity);
        m_begin = m_end = pointer(a_malloc(m_capacity));
    }

    // fill empty vector with given value
    void assign_fill(size_type count, const T& value)
    {
        safe_grow(count);
        fill(m_begin, count, value);
        m_end = m_begin + count;
    }

    // fill empty vector with values from [first;last)
    template <class InputIterator> void assign_copy(InputIterator first, InputIterator last)
    {
        auto count = last - first;
        safe_grow(count);
        copy_not_aliased(m_begin, first, last);
        m_end = m_begin + count;
    }

    // allocator wrappers for aligned allocations
    static constexpr bool allocator_aligned()
    {
        return Alloc::alloc_align() >= alignof(value_type);
    }

    void* real_addr(void* ptr) const
    {
        if (allocator_aligned())
            return ptr; // pointer was not changed

        if (!ptr)
            return nullptr;

        // byte before ptr is offset
        // (we should use byte here, but we don't have c++17 guaranteed)
        uint8_t* byte_buf = reinterpret_cast<uint8_t*>(ptr);
        auto     offset   = *(byte_buf - 1);
        return byte_buf - offset;
    }

    void* align_ptr(void* ptr) const
    {
        if (!ptr)
            return nullptr;

        uintptr_t addr   = reinterpret_cast<uintptr_t>(ptr);
        auto      offset = alignof(T) - addr % alignof(T);

        uint8_t* fix = reinterpret_cast<uint8_t*>(ptr);
        fix += offset;
        *(fix - 1) = uint8_t(offset);
        return fix;
    }

    void* a_malloc(size_type num_elements)
    {
        if (allocator_aligned())
        {
            return Alloc::malloc(e2b(num_elements));
        }

        // allocate 1 alignment more than needed,
        // thus we can shift by at least one byte to get the appropriate one
        // and have 1 byte before the pointer to show us how much we shifted
        auto buf = Alloc::malloc(e2b(num_elements) + alignof(value_type));
        return align_ptr(buf);
    }

    void a_realloc_begin(size_type num_elements)
    {
        if (allocator_aligned())
        {
            m_begin = pointer(Alloc::realloc(m_begin, e2b(num_elements)));
        }
        else
        {
            // allocator alignment doesn't match out required one
            // sadly, we can't use realloc
            // if it ends up returning a different address it may be such that the data copied by the
            // allocator's realloc has a different alignment than what's needed
            // we could memmove if this is the case, but for now we will just malloc-copy
            // it should be rare anyway
            auto new_buf = a_malloc(num_elements);
            if (m_begin)
            {
                std::memcpy(new_buf, m_begin, e2b(size()));
                a_free_begin();
            }
            m_begin = pointer(new_buf);
        }

        m_capacity = num_elements;
    }

    bool a_expand_begin(size_type num_elements)
    {
        if (allocator_aligned())
        {
            if (!Alloc::expand(m_begin, e2b(num_elements)))
                return false;
        }
        else
        {
            auto ptr = real_addr(m_begin);
            if (!Alloc::expand(ptr, e2b(num_elements) + alignof(value_type)))
                return false;
        }

        m_capacity = num_elements;
        return true;
    }

    void a_free_begin()
    {
        if (allocator_aligned())
        {
            Alloc::free(m_begin);
        }
        else
        {
            Alloc::free(real_addr(m_begin));
        }
    }

    static constexpr size_t e2b(size_t num_elements)
    {
        return num_elements * sizeof(T);
    }

    // ref getters for easier usage
    allocator_type& get_alloc()
    {
        return *this;
    }
    const allocator_type& get_alloc() const
    {
        return *this;
    }

    pointer m_begin;
    pointer m_end;

    size_t m_capacity;
};

template <typename T, class Alloc>
bool operator==(const pod_vector<T, Alloc>& a, const pod_vector<T, Alloc>& b)
{
    if (a.size() != b.size())
        return false;
    if (a.empty())
        return true;
    return std::memcmp(a.data(), b.data(), a.byte_size()) == 0;
}

template <typename T, class Alloc>
bool operator!=(const pod_vector<T, Alloc>& a, const pod_vector<T, Alloc>& b)
{
    if (a.size() != b.size())
        return true;
    if (a.empty())
        return false;
    return std::memcmp(a.data(), b.data(), a.byte_size()) != 0;
}

} // namespace itlib
