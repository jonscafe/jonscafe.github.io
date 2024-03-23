import splashData from '@/data/splashData'
import { useEffect, useRef } from 'react'
import { disableBodyScroll, enableBodyScroll, clearAllBodyScrollLocks } from 'body-scroll-lock'
import sample from 'lodash/sample'

const prepareNode = (text: string, node: HTMLElement): HTMLElement => {
  node.innerHTML = ''
  node.classList.add('relative')
  const placeholder = document.createElement('div')
  placeholder.classList.add('invisible')
  placeholder.innerHTML = text
  const animator = document.createElement('div')
  animator.classList.add('absolute', 'top-0', 'left-0')
  animator.dataset.text = text
  node.appendChild(placeholder)
  node.appendChild(animator)
  return animator
}

const animateNode = (node: HTMLElement) => {
  const full = node.dataset.text
  const chars = [...full.matchAll(/(<.+?>.?|.)/g)].map((c) => c[0])
  let index = 1
  const animate = () => {
    node.innerHTML = chars.slice(0, index).join('')
    if (index < chars.length) {
      index++
      setTimeout(animate, 25)
    }
  }
  animate()
}

const hideSplash = (node: HTMLElement) => {
  enableBodyScroll(node)
  clearAllBodyScrollLocks()

  node.classList.add('opacity-0', '-translate-y-full')
  setTimeout(() => {
    node.classList.add('hidden')
  }, 1000)
}

const Splashscreen = () => {
  const splashRef = useRef(null)
  const lineContainerRef = useRef(null)
  const titleRef = useRef(null)

  useEffect(() => {
    if (splashRef.current) {
      const { lyrics, title } = sample(splashData)
      const lines = lyrics.split('\n')
      const lineNodes = []

      lineContainerRef.current.innerHTML = ''
      lineContainerRef.current.classList.remove('opacity-0', '-translate-y-full')
      lines.forEach((line) => {
        const lineNode = document.createElement('div')
        const animatorNode = prepareNode(line, lineNode)
        lineContainerRef.current.appendChild(lineNode)
        lineNodes.push(animatorNode)
      })

      const animatorNode = prepareNode('' + title, titleRef.current)
      lineNodes.push(animatorNode)

      lineNodes.forEach((node, index) => {
        setTimeout(() => {
          animateNode(node)
        }, index * 200)
      })

      setTimeout(() => {
        hideSplash(splashRef.current)
      }, 2000)

      splashRef.current.classList.remove('hidden')
      disableBodyScroll(splashRef.current)
    }
  }, [])

  return (
    <div
      lang="ja"
      ref={splashRef}
      style={{ fontFeatureSettings: "'palt' 1" }}
      className="fixed inset-0 flex items-center justify-center transition-all duration-1000 bg-slate-900"
    >
      <button className="absolute top-0 right-0 p-4" onClick={() => hideSplash(splashRef.current)}>
        Skip
      </button>
      <code className="absolute text-6xl font-extrabold sm:text-8xl text-white/25 top-4 left-4">
        {'SNI'}
      </code>
      <div className="">
        <div
          ref={lineContainerRef}
          className="text-xl leading-tight xl:leading-tight lg:leading-tight md:leading-tight sm:leading-tight xl:text-5xl lg:text-4xl md:text-3xl sm:text-2xl"
        >
          <div>Lets</div>
          <div>Go To</div>
          <div>Berlin</div>
        </div>
        <div className="mt-2" ref={titleRef}>
          Suntikan Bambang Berlin
        </div>
      </div>
      <code className="absolute text-6xl font-extrabold sm:text-8xl text-white/25 bottom-4 right-4">
        {'SNI'}
      </code>
    </div>
  )
}

export default Splashscreen
