use std::{
    fmt::Debug,
    ops::Deref,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
};

use tracing::{error, info};

#[derive(Debug)]
pub struct NoisyArc<T: ?Sized> {
    ptr: Arc<NoisyArcInner<T>>,

    /// unique id for this ref to the inner
    id: u64,
}

impl<T> NoisyArc<T> {
    pub fn as_ref(&self) -> &T {
        self.ptr.inner.as_ref()
    }
}

impl<T: ?Sized + Debug> Clone for NoisyArc<T> {
    fn clone(&self) -> Self {
        let res = Self { ptr: self.ptr.clone(), id: self.ptr.get_next_id() };
        info!(
            "NoisyArc::clone {:?} -> {}. Refcount now {}",
            self.ptr.inner,
            res.id,
            Arc::strong_count(&self.ptr)
        );
        res
    }
}

impl<T: ?Sized> Drop for NoisyArc<T> {
    fn drop(&mut self) {
        info!("NoisyArc::drop({}). Refcount before drop {}", self.id, Arc::strong_count(&self.ptr));
    }
}

impl<T: ?Sized> Deref for NoisyArc<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        self.ptr.inner.deref()
    }
}

impl<T: Debug + ?Sized> NoisyArc<T> {
    pub fn new(data: T) -> NoisyArc<T>
    where
        T: Sized,
    {
        Self::from_box(Box::new(data))
    }

    pub fn from_box(inner: Box<T>) -> NoisyArc<T> {
        use uuid::Uuid;

        Self {
            ptr: Arc::new(NoisyArcInner {
                inner,
                next_id: AtomicU64::new(1),
                base_id: Uuid::new_v4().to_string(),
            }),
            id: 0,
        }
    }

    // SAFETY: T and U must be compatible types such that transmuting between
    // them directly would be acceptable.
    pub unsafe fn transmute<U: Debug + ?Sized>(self) -> NoisyArc<U> {
        let id = self.id;
        let ptr = Arc::into_raw(self.ptr.clone());
        drop(self);

        // SAFETY: T and U are compatible for transmuting, NoisyArcInner is
        // #[repr(C)], thus NoisyArcInner<T> and NoisyArcInner<U> have the same
        // layout and safety invariants.
        let ptr = unsafe { Arc::from_raw(ptr as _) };
        let res = NoisyArc { ptr, id };

        error!(
            "NoisyArc::transmute {:?}. Refcount now {}",
            res.ptr.inner,
            Arc::strong_count(&res.ptr)
        );
        res
    }
}

#[derive(Debug)]
#[repr(C)]
pub struct NoisyArcInner<T: ?Sized> {
    inner: Box<T>,
    base_id: String,
    next_id: AtomicU64,
}

impl<T: ?Sized> NoisyArcInner<T> {
    pub fn get_next_id(&self) -> u64 {
        return self.next_id.fetch_add(1, Ordering::SeqCst);
    }
}
