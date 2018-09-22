package ping

// ElementMapper provides an identity mapping by default.
//
// This can be replaced to provide a struct that maps elements to linker
// objects, if they are not the same. An ElementMapper is not typically
// required if: Linker is left as is, Element is left as is, or Linker and
// Element are the same type.
type pingPacketElementMapper struct{}

// linkerFor maps an Element to a Linker.
//
// This default implementation should be inlined.
//
//go:nosplit
func (pingPacketElementMapper) linkerFor(elem *pingPacket) *pingPacket { return elem }

// List is an intrusive list. Entries can be added to or removed from the list
// in O(1) time and with no additional memory allocations.
//
// The zero value for List is an empty list ready to use.
//
// To iterate over a list (where l is a List):
//      for e := l.Front(); e != nil; e = e.Next() {
// 		// do something with e.
//      }
//
// +stateify savable
type pingPacketList struct {
	head *pingPacket
	tail *pingPacket
}

// Reset resets list l to the empty state.
func (l *pingPacketList) Reset() {
	l.head = nil
	l.tail = nil
}

// Empty returns true iff the list is empty.
func (l *pingPacketList) Empty() bool {
	return l.head == nil
}

// Front returns the first element of list l or nil.
func (l *pingPacketList) Front() *pingPacket {
	return l.head
}

// Back returns the last element of list l or nil.
func (l *pingPacketList) Back() *pingPacket {
	return l.tail
}

// PushFront inserts the element e at the front of list l.
func (l *pingPacketList) PushFront(e *pingPacket) {
	pingPacketElementMapper{}.linkerFor(e).SetNext(l.head)
	pingPacketElementMapper{}.linkerFor(e).SetPrev(nil)

	if l.head != nil {
		pingPacketElementMapper{}.linkerFor(l.head).SetPrev(e)
	} else {
		l.tail = e
	}

	l.head = e
}

// PushBack inserts the element e at the back of list l.
func (l *pingPacketList) PushBack(e *pingPacket) {
	pingPacketElementMapper{}.linkerFor(e).SetNext(nil)
	pingPacketElementMapper{}.linkerFor(e).SetPrev(l.tail)

	if l.tail != nil {
		pingPacketElementMapper{}.linkerFor(l.tail).SetNext(e)
	} else {
		l.head = e
	}

	l.tail = e
}

// PushBackList inserts list m at the end of list l, emptying m.
func (l *pingPacketList) PushBackList(m *pingPacketList) {
	if l.head == nil {
		l.head = m.head
		l.tail = m.tail
	} else if m.head != nil {
		pingPacketElementMapper{}.linkerFor(l.tail).SetNext(m.head)
		pingPacketElementMapper{}.linkerFor(m.head).SetPrev(l.tail)

		l.tail = m.tail
	}

	m.head = nil
	m.tail = nil
}

// InsertAfter inserts e after b.
func (l *pingPacketList) InsertAfter(b, e *pingPacket) {
	a := pingPacketElementMapper{}.linkerFor(b).Next()
	pingPacketElementMapper{}.linkerFor(e).SetNext(a)
	pingPacketElementMapper{}.linkerFor(e).SetPrev(b)
	pingPacketElementMapper{}.linkerFor(b).SetNext(e)

	if a != nil {
		pingPacketElementMapper{}.linkerFor(a).SetPrev(e)
	} else {
		l.tail = e
	}
}

// InsertBefore inserts e before a.
func (l *pingPacketList) InsertBefore(a, e *pingPacket) {
	b := pingPacketElementMapper{}.linkerFor(a).Prev()
	pingPacketElementMapper{}.linkerFor(e).SetNext(a)
	pingPacketElementMapper{}.linkerFor(e).SetPrev(b)
	pingPacketElementMapper{}.linkerFor(a).SetPrev(e)

	if b != nil {
		pingPacketElementMapper{}.linkerFor(b).SetNext(e)
	} else {
		l.head = e
	}
}

// Remove removes e from l.
func (l *pingPacketList) Remove(e *pingPacket) {
	prev := pingPacketElementMapper{}.linkerFor(e).Prev()
	next := pingPacketElementMapper{}.linkerFor(e).Next()

	if prev != nil {
		pingPacketElementMapper{}.linkerFor(prev).SetNext(next)
	} else {
		l.head = next
	}

	if next != nil {
		pingPacketElementMapper{}.linkerFor(next).SetPrev(prev)
	} else {
		l.tail = prev
	}
}

// Entry is a default implementation of Linker. Users can add anonymous fields
// of this type to their structs to make them automatically implement the
// methods needed by List.
//
// +stateify savable
type pingPacketEntry struct {
	next *pingPacket
	prev *pingPacket
}

// Next returns the entry that follows e in the list.
func (e *pingPacketEntry) Next() *pingPacket {
	return e.next
}

// Prev returns the entry that precedes e in the list.
func (e *pingPacketEntry) Prev() *pingPacket {
	return e.prev
}

// SetNext assigns 'entry' as the entry that follows e in the list.
func (e *pingPacketEntry) SetNext(elem *pingPacket) {
	e.next = elem
}

// SetPrev assigns 'entry' as the entry that precedes e in the list.
func (e *pingPacketEntry) SetPrev(elem *pingPacket) {
	e.prev = elem
}
