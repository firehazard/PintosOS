#ifndef RING_BUFFER_H
#define RING_BUFFER_H

/* Returned by rb_pop_front() when the ring_buffer is empty */
#define RING_BUFFER_EMPTY -1

/* struct ring_buffer
 * ------------------
 * Simple circular buffer of int's
 * Citation: Based on the ring_buffer implementation detailed at this URL:
 * http://www.embedded.com/shared/printableArticle.jhtml?articleID=15300198
 */

struct ring_buffer
{
  unsigned int *buffer;
  unsigned int head, tail, size;
};

/* Utility functions for ring-buffer
 * ---------------------------------
 */

/* Returns the next position after posn in the ring buffer b */
static inline int
rb_inc_position(struct ring_buffer const *b, int posn)
{
  if (++posn >= (int)b->size)
    posn = 0;
  return posn;
}

/* Checks whether the given ring_buffer is empty */
static inline bool 
rb_empty(struct ring_buffer const *b)
{
  return b->head == b->tail;
}

/* Checks whether the given ring_buffer is full */
static inline bool 
rb_full(struct ring_buffer const *b)
{
  return rb_inc_position(b, b->tail) == (int)b->head;
}

/* Removes and returns the first entry in the ring_buffer.  If the
   buffer is empty, returns RING_BUFFER_EMPTY. */
static inline int
rb_pop_front(struct ring_buffer *b)
{  
  if (rb_empty(b)) 
    {
      return RING_BUFFER_EMPTY; 
    }
  else 
    {
      int to_return = (int)b->buffer[b->head];
      b->head = rb_inc_position(b, b->head);
      return to_return;
    }
}

/* Adds the given val to the tail of the ring_buffer. */
static inline bool
rb_push_back(struct ring_buffer *b, int val)
{
  if (rb_full(b)) 
    return false;
  
  b->buffer[b->tail] = val;
  b->tail = rb_inc_position(b, b->tail);
  return true;
}

static inline bool
rb_copy_buff(struct ring_buffer *dest, struct ring_buffer const *src,
	     int dest_size)
{
  unsigned int dest_pos, src_pos;

  /* Copy buffer */
  src_pos = src->head;
  for (dest_pos = 0; dest_pos < src->size && dest_pos < dest->size; dest_pos++)
    {
      dest[dest_pos] = src[src_pos];
      src_pos = rb_inc_position(src, src_pos);    
    }
  
  /* Set size */
  dest->size = dest_size;
  
  /* Set head and tail */
  dest->head = 0;  
  dest->tail = (src->size + src->tail - src->head) % src->size;
  
  /* Return val indicates whether we had enough space to copy entire
     src array. */
  return (dest_pos == src->size);
}

static inline void
rb_init_buff(struct ring_buffer *me, int me_size)
{
 
  /* Set size */
  me->size = me_size;
  
  /* Set head and tail */
  me->head = 0;  
  me->tail = 0;
}

#endif /* userprog/ring-buffer.h */
