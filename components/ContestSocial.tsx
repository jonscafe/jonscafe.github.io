import { Fragment, useRef, useState, useCallback } from 'react'
import { Dialog, Transition } from '@headlessui/react'
import domtoimage from 'dom-to-image'

export default function ContestSocial({
  open,
  setOpen,
  name,
  place,
  ctfPoints,
}: {
  open: boolean
  setOpen: (open: boolean) => void
  name: string
  place: number
  ctfPoints: number
}) {
  const cancelButtonRef = useRef(null)
  const [image, setImage] = useState<string | null>(null)
  const designRef = useCallback((designRef) => {
    if (designRef) {
      setTimeout(() => domtoimage.toPng(designRef).then(setImage), 100)
    }
  }, [])

  return (
    <Transition.Root show={open} as={Fragment}>
      <Dialog
        as="div"
        className="fixed inset-0 z-10 overflow-y-auto"
        initialFocus={cancelButtonRef}
        onClose={setOpen}
      >
        <div className="flex items-end justify-center min-h-screen px-4 pt-4 pb-20 text-center sm:block sm:p-0">
          <Transition.Child
            as={Fragment}
            enter="ease-out duration-300"
            enterFrom="opacity-0"
            enterTo="opacity-100"
            leave="ease-in duration-200"
            leaveFrom="opacity-100"
            leaveTo="opacity-0"
          >
            <Dialog.Overlay className="fixed inset-0 transition-opacity bg-gray-800 bg-opacity-75" />
          </Transition.Child>

          {/* This element is to trick the browser into centering the modal contents. */}
          <span className="hidden sm:inline-block sm:align-middle sm:h-screen" aria-hidden="true">
            &#8203;
          </span>
          <Transition.Child
            as={Fragment}
            enter="ease-out duration-300"
            enterFrom="opacity-0 translate-y-4 sm:translate-y-0 sm:scale-95"
            enterTo="opacity-100 translate-y-0 sm:scale-100"
            leave="ease-in duration-200"
            leaveFrom="opacity-100 translate-y-0 sm:scale-100"
            leaveTo="opacity-0 translate-y-4 sm:translate-y-0 sm:scale-95"
          >
            <div className="inline-block overflow-hidden text-left align-bottom transition-all transform bg-gray-900 rounded-lg shadow-xl sm:my-8 sm:align-middle md:w-fit sm:w-full">
              <div className="px-4 pt-5 pb-4 bg-gray-900 sm:p-6 sm:pb-4 w-fit">
                <div className="relative">
                  <div
                    ref={designRef}
                    className="w-[1000px] h-[500px] bg-cover bg-center bg-no-repeat text-black"
                    style={{ backgroundImage: 'url(/static/images/sekai-bg.jpg)' }}
                  >
                    <div
                      className={
                        (place == 1
                          ? 'from-yellow-500 to-yellow-700 after:border-yellow-700'
                          : 'from-rose-600 to-rose-800 after:border-rose-800') +
                        ' h-[10rem] ml-8 pb-3 flex relative items-end justify-center text-white z-1 w-32 bg-gradient-to-b after:w-32 after:box-border after:absolute after:left-0 after:top-full after:h-8 after:border-l-[4rem] after:border-r-[4rem] after:border-b-[4rem] after:border-b-transparent'
                      }
                    >
                      <span
                        className={
                          (place >= 100
                            ? ''
                            : place >= 10
                            ? 'text-6xl font-semibold'
                            : place >= 2
                            ? 'text-6xl font-bold'
                            : 'text-7xl font-bold') + ' inline-block leading-none'
                        }
                      >
                        <sup>#</sup>
                        {place}
                      </span>
                    </div>
                    <div className="absolute w-8/12 left-8 bottom-8">
                      <h4 className="text-3xl font-semibold">{ctfPoints} pts</h4>
                      <h1 className="text-6xl font-bold">{name}</h1>
                    </div>
                    <img
                      src="/static/images/fullLogo.png"
                      alt="Logo"
                      className="absolute w-3/12 top-8 right-8"
                    />
                  </div>
                  <img
                    src={image}
                    alt="Share this for contest"
                    className="w-[1000px] h-[500px] absolute top-0 left-0 -z-1"
                  />
                </div>
              </div>
              <div className="px-4 py-3 bg-gray-800 sm:px-6 sm:flex sm:flex-row-reverse">
                <button
                  type="button"
                  className="inline-flex justify-center w-full px-4 py-2 mt-3 text-base font-medium text-white bg-gray-700 border border-gray-700 rounded-md shadow-sm hover:bg-gray-600 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-indigo-500 sm:mt-0 sm:ml-3 sm:w-auto sm:text-sm"
                  onClick={() => setOpen(false)}
                  ref={cancelButtonRef}
                >
                  Close
                </button>
              </div>
            </div>
          </Transition.Child>
        </div>
      </Dialog>
    </Transition.Root>
  )
}
